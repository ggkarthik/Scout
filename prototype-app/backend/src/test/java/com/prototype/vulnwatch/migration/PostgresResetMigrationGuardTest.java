package com.prototype.vulnwatch.migration;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

class PostgresResetMigrationGuardTest {

    private static final int LAST_LEGACY_MIGRATION_VERSION = 27;
    private static final Pattern MIGRATION_VERSION = Pattern.compile("^V(\\d+)__.*\\.sql$");
    private static final Pattern TENANT_DEFAULT_DDL =
            Pattern.compile("(?is)\\b(?:create|alter|drop)\\s+(?:table|index|sequence|view)\\s+(?:if\\s+(?:not\\s+)?exists\\s+)?tenant_default\\.");
    private static final Pattern UNQUALIFIED_TENANT_DDL =
            Pattern.compile("(?is)\\b(?:create|alter|drop)\\s+(?:table|index|sequence|view)\\s+(?:if\\s+(?:not\\s+)?exists\\s+)?(?!platform\\.|tenant_default\\.|information_schema\\.|pg_catalog\\.)[a-z_][a-z0-9_]*\\b");

    @Test
    void newPerTenantMigrationsMustUseAllSchemaLoopOrFlywayPerSchemaMechanism() throws IOException {
        Path migrationDir = Path.of("src/main/resources/db/migration/postgres_reset");
        try (var files = Files.list(migrationDir)) {
            var violations = files
                    .filter(path -> path.getFileName().toString().endsWith(".sql"))
                    .filter(path -> migrationVersion(path) > LAST_LEGACY_MIGRATION_VERSION)
                    .filter(path -> isDriftProne(path, read(path)))
                    .map(Path::getFileName)
                    .map(Path::toString)
                    .toList();

            assertThat(violations)
                    .as("New per-tenant DDL must loop over tenant schemas instead of changing only tenant_default")
                    .isEmpty();
        }
    }

    private boolean isDriftProne(Path path, String sql) {
        if (usesAllSchemaLoop(sql) || approvedFlywayPerSchema(sql) || platformOnly(sql)) {
            return false;
        }
        return TENANT_DEFAULT_DDL.matcher(sql).find() || UNQUALIFIED_TENANT_DDL.matcher(sql).find();
    }

    private boolean usesAllSchemaLoop(String sql) {
        String normalized = sql.toLowerCase();
        return normalized.contains("information_schema.tables")
                && normalized.contains("table_schema")
                && normalized.contains("loop");
    }

    private boolean approvedFlywayPerSchema(String sql) {
        return sql.contains("migration-guard: flyway-per-schema");
    }

    private boolean platformOnly(String sql) {
        return sql.contains("migration-guard: platform-only") && !sql.contains("tenant_default.");
    }

    private int migrationVersion(Path path) {
        Matcher matcher = MIGRATION_VERSION.matcher(path.getFileName().toString());
        return matcher.matches() ? Integer.parseInt(matcher.group(1)) : Integer.MAX_VALUE;
    }

    private String read(Path path) {
        try {
            return Files.readString(path);
        } catch (IOException ex) {
            throw new IllegalStateException("Unable to read migration " + path, ex);
        }
    }
}
