package com.prototype.vulnwatch.architecture;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

class ServiceLayerSchemaIsolationTest {

    private static final Path SERVICE_ROOT = Path.of("src/main/java/com/prototype/vulnwatch/service");

    private static final List<Pattern> FORBIDDEN_PATTERNS = List.of(
            Pattern.compile("\\bfindByTenantAnd"),
            Pattern.compile("\\bcountByTenantAnd"),
            Pattern.compile("\\bfindByTenantOrderBy"),
            Pattern.compile("\\bcountByTenant\\("),
            Pattern.compile("tenant\\.id\\s*=\\s*:tenantId")
    );

    @Test
    void serviceLayerDoesNotUseSharedSchemaTenantQualifiedAccessPatterns() throws IOException {
        List<String> violations = new ArrayList<>();
        try (Stream<Path> files = Files.walk(SERVICE_ROOT)) {
            files.filter(path -> path.toString().endsWith(".java"))
                    .forEach(path -> collectViolations(path, violations));
        }

        assertTrue(
                violations.isEmpty(),
                () -> "Found tenant-qualified shared-schema access patterns in service layer:\n" + String.join("\n", violations)
        );
    }

    private static void collectViolations(Path path, List<String> violations) {
        List<String> lines;
        try {
            lines = Files.readAllLines(path);
        } catch (IOException e) {
            throw new RuntimeException("Failed to read " + path, e);
        }

        for (int index = 0; index < lines.size(); index++) {
            String line = lines.get(index);
            for (Pattern pattern : FORBIDDEN_PATTERNS) {
                if (pattern.matcher(line).find()) {
                    violations.add(path + ":" + (index + 1) + ": " + line.trim());
                }
            }
        }
    }
}
