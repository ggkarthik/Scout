package com.prototype.vulnwatch.migration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

class MigrationCatalogTest {

    private static final Path MIGRATION_DIR = Path.of("src/main/resources/db/migration/postgres_reset");
    private static final Pattern VERSION_PATTERN = Pattern.compile("^V(\\d+)__.+\\.sql$");

    @Test
    void migrationsHaveUniqueVersionsMeaningfulSqlAndNoUnexpectedDuplicateBodies() throws IOException {
        List<MigrationFile> migrations = Files.list(MIGRATION_DIR)
                .filter(path -> path.getFileName().toString().endsWith(".sql"))
                .map(MigrationCatalogTest::toMigrationFile)
                .sorted(Comparator.comparing(MigrationFile::version))
                .toList();

        Map<String, List<String>> filesByVersion = new LinkedHashMap<>();
        Map<String, List<String>> filesByNormalizedSql = new LinkedHashMap<>();
        List<String> unexpectedCommentOnly = new ArrayList<>();

        for (MigrationFile migration : migrations) {
            filesByVersion.computeIfAbsent(migration.version(), ignored -> new ArrayList<>())
                    .add(migration.fileName());

            if (migration.normalizedSql().isBlank()) {
                unexpectedCommentOnly.add(migration.fileName());
                continue;
            }

            filesByNormalizedSql.computeIfAbsent(migration.normalizedSql(), ignored -> new ArrayList<>())
                    .add(migration.version());
        }

        List<String> duplicateVersions = filesByVersion.entrySet().stream()
                .filter(entry -> entry.getValue().size() > 1)
                .map(entry -> entry.getKey() + " -> " + entry.getValue())
                .toList();
        assertTrue(duplicateVersions.isEmpty(), "Duplicate Flyway versions found: " + duplicateVersions);

        assertTrue(
                unexpectedCommentOnly.isEmpty(),
                "Comment-only or whitespace-only migrations found: " + unexpectedCommentOnly
        );

        List<String> unexpectedDuplicateBodies = new ArrayList<>();
        for (List<String> versions : filesByNormalizedSql.values()) {
            if (versions.size() <= 1) {
                continue;
            }
            Set<String> duplicateSet = Set.copyOf(versions);
            unexpectedDuplicateBodies.add(duplicateSet.toString());
        }

        assertTrue(
                unexpectedDuplicateBodies.isEmpty(),
                "Unexpected duplicate migration bodies found: " + unexpectedDuplicateBodies
        );
        assertEquals(1, migrations.size(), "Expected a single bootstrap migration in the reset catalog.");
    }

    private static MigrationFile toMigrationFile(Path path) {
        String fileName = path.getFileName().toString();
        Matcher matcher = VERSION_PATTERN.matcher(fileName);
        if (!matcher.matches()) {
            fail("Unexpected migration filename: " + fileName);
        }
        try {
            String sql = Files.readString(path, StandardCharsets.UTF_8);
            return new MigrationFile(matcher.group(1), fileName, normalizeSql(sql));
        } catch (IOException exception) {
            throw new IllegalStateException("Failed to read migration " + fileName, exception);
        }
    }

    private static String normalizeSql(String sql) {
        String withoutBlockComments = sql.replaceAll("(?s)/\\*.*?\\*/", " ");
        String withoutLineComments = withoutBlockComments.replaceAll("(?m)--.*$", " ");
        return withoutLineComments
                .replaceAll("\\s+", " ")
                .trim();
    }

    private record MigrationFile(String version, String fileName, String normalizedSql) {
    }
}
