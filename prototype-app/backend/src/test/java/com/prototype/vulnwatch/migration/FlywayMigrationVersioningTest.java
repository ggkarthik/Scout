package com.prototype.vulnwatch.migration;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

class FlywayMigrationVersioningTest {

    private static final Pattern VERSIONED_MIGRATION = Pattern.compile("^V(\\d+)__(.+)\\.sql$");
    private static final Path MIGRATION_DIR = Path.of("src/main/resources/db/migration/postgres_reset");

    @Test
    void versionedMigrationsUseUniqueVersions() throws IOException {
        Map<Integer, List<String>> filesByVersion = new LinkedHashMap<>();

        try (var paths = Files.list(MIGRATION_DIR)) {
            paths.filter(Files::isRegularFile)
                    .map(path -> path.getFileName().toString())
                    .sorted()
                    .forEach(fileName -> {
                        Matcher matcher = VERSIONED_MIGRATION.matcher(fileName);
                        if (!matcher.matches()) {
                            return;
                        }
                        int version = Integer.parseInt(matcher.group(1));
                        filesByVersion.computeIfAbsent(version, ignored -> new ArrayList<>()).add(fileName);
                    });
        }

        List<String> duplicates = filesByVersion.entrySet().stream()
                .filter(entry -> entry.getValue().size() > 1)
                .sorted(Comparator.comparingInt(Map.Entry::getKey))
                .map(entry -> "V" + entry.getKey() + " -> " + entry.getValue())
                .toList();

        assertTrue(duplicates.isEmpty(),
                () -> "Duplicate Flyway migration versions detected: " + String.join("; ", duplicates));
    }
}
