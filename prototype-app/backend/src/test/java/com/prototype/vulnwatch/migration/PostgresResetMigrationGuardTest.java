package com.prototype.vulnwatch.migration;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

class PostgresResetMigrationGuardTest {

    private static final String HEADER = "-- migration-guard: platform-only";
    private static final Pattern VERSION = Pattern.compile("^V(\\d+)__.+\\.sql$");
    private static final Pattern TENANT_DEFAULT = Pattern.compile(
            "(?i)(?:\\\"tenant_default\\\"|tenant_default)\\s*\\.");
    private static final Pattern DYNAMIC_SQL = Pattern.compile(
            "(?is)\\bexecute\\s+(?:format\\s*\\(|['\\\"])");
    private static final String QUALIFIED_PLATFORM = "(?:\\\"?platform\\\"?\\s*\\.\\s*)";
    private static final String IDENTIFIER = "\\\"?[a-z_][a-z0-9_]*\\\"?";
    private static final List<String> OBJECT_PREFIXES = List.of(
            "\\b(?:create|alter|drop|truncate)\\s+(?:table|sequence|view|policy)\\s+(?:if\\s+(?:not\\s+)?exists\\s+)?",
            "\\binsert\\s+into\\s+",
            "(?<!before )(?<!do )(?<!after )\\bupdate\\s+(?!of\\b|on\\b)",
            "\\bdelete\\s+from\\s+",
            "\\breferences\\s+");
    private static final Pattern UNQUALIFIED_INDEX_TARGET = Pattern.compile(
            "(?is)\\bcreate\\s+(?:unique\\s+)?index\\s+(?:concurrently\\s+)?"
                    + "(?:if\\s+not\\s+exists\\s+)?\\S+\\s+on\\s+(?:only\\s+)?"
                    + "(?!\\\"?platform\\\"?\\s*\\.)\\\"?[a-z_][a-z0-9_]*\\\"?");

    @Test
    void sharedGuardFixturesHaveExpectedResults() throws Exception {
        Path fixtures = Path.of("../../.github/scripts/fixtures/tenant-migration-guard-cases.json");
        JsonNode cases = new ObjectMapper().readTree(Files.readString(fixtures));
        List<String> mismatches = new ArrayList<>();
        for (JsonNode fixture : cases) {
            boolean actual = violations(fixture.path("sql").asText()).isEmpty();
            if (actual != fixture.path("valid").asBoolean()) {
                mismatches.add(fixture.path("name").asText() + " expected="
                        + fixture.path("valid").asBoolean() + " actual=" + actual);
            }
        }
        assertThat(mismatches).isEmpty();
    }

    @Test
    void platformMigrationsAreStrictlyPlatformOnlyAndSubstantive() throws Exception {
        Path migrationDir = Path.of("src/main/resources/db/migration/postgres_reset");
        List<String> failures = new ArrayList<>();
        try (var files = Files.list(migrationDir)) {
            for (Path migration : files.filter(path -> path.getFileName().toString().endsWith(".sql")).toList()) {
                Matcher matcher = VERSION.matcher(migration.getFileName().toString());
                if (!matcher.matches()) {
                    failures.add("malformed filename: " + migration.getFileName());
                    continue;
                }
                String sql = Files.readString(migration);
                if (withoutComments(sql).isBlank()) {
                    failures.add(migration.getFileName() + ": comment-only migration");
                    continue;
                }
                if (Integer.parseInt(matcher.group(1)) == 1) {
                    if (!sql.startsWith(HEADER) || sql.contains("${tenantId}") || sql.contains("${tenantSchema}")) {
                        failures.add(migration.getFileName() + ": reset baseline contains tenant placeholders or missing header");
                    }
                    continue;
                }
                for (String violation : violations(sql)) {
                    failures.add(migration.getFileName() + ": " + violation);
                }
            }
        }
        assertThat(failures).isEmpty();
    }

    @Test
    void tenantMigrationsHaveNumericNamesAndSubstantiveSql() throws Exception {
        Path migrationDir = Path.of("src/main/resources/db/migration/tenant");
        List<String> failures = new ArrayList<>();
        try (var files = Files.list(migrationDir)) {
            for (Path migration : files.filter(path -> path.getFileName().toString().endsWith(".sql")).toList()) {
                if (!VERSION.matcher(migration.getFileName().toString()).matches()) {
                    failures.add("malformed filename: " + migration.getFileName());
                } else if (withoutComments(Files.readString(migration)).isBlank()) {
                    failures.add("comment-only migration: " + migration.getFileName());
                }
            }
        }
        assertThat(failures).isEmpty();
    }

    private static List<String> violations(String sql) {
        List<String> failures = new ArrayList<>();
        if (sql.lines().findFirst().filter(HEADER::equals).isEmpty()) {
            failures.add("missing exact first-line header");
        }
        String body = withoutComments(sql);
        if (TENANT_DEFAULT.matcher(body).find()) {
            failures.add("references tenant_default");
        }
        if (DYNAMIC_SQL.matcher(body).find()) {
            failures.add("contains dynamic SQL");
        }
        String analysis = body.replaceAll("'(?:''|[^'])*'", "''").toLowerCase(Locale.ROOT);
        for (String prefix : OBJECT_PREFIXES) {
            Matcher matcher = Pattern.compile(prefix + "(" + QUALIFIED_PLATFORM + ")?" + IDENTIFIER,
                    Pattern.CASE_INSENSITIVE | Pattern.DOTALL).matcher(analysis);
            while (matcher.find()) {
                if (matcher.group(1) == null) {
                    failures.add("contains unqualified DDL/DML/reference");
                    break;
                }
            }
        }
        if (UNQUALIFIED_INDEX_TARGET.matcher(analysis).find()) {
            failures.add("contains unqualified index target");
        }
        return failures;
    }

    private static String withoutComments(String sql) {
        return sql.replaceAll("(?s)/\\*.*?\\*/", " ").replaceAll("(?m)--[^\\n]*", " ");
    }

    private static String sha256(Path path) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)));
    }
}
