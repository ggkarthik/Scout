package com.prototype.vulnwatch.migration;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class RuntimeOverlayMigrationCompatibilityTest {
    @Test
    void v8IsIndexOnlyAndDoesNotRaiseTheV7CompatibilityFloor() throws Exception {
        String migration = Files.readString(Path.of(
                "src/main/resources/db/migration/tenant/V8__index_runtime_relationship_overlay.sql")).toLowerCase();
        assertTrue(migration.contains("create index"));
        assertFalse(migration.contains("alter table"));
        assertFalse(migration.contains("create table"));

        String application = Files.readString(Path.of("src/main/resources/application.yml"));
        String production = Files.readString(Path.of("src/main/resources/application-prod.yml"));
        String schemaService = Files.readString(Path.of(
                "src/main/java/com/prototype/vulnwatch/service/TenantSchemaService.java"));
        assertTrue(application.contains("minimum-compatible-schema-version: ${APP_MINIMUM_TENANT_SCHEMA_VERSION:7}"));
        assertTrue(production.contains("minimum-compatible-schema-version: 7"));
        assertTrue(schemaService.contains("minimum-compatible-schema-version:7"));
    }
}
