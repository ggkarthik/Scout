package com.prototype.vulnwatch.service;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class DatabaseResetCompatibilityGuardService {

    private static final String LEGACY_PUBLIC_TABLES_SQL = """
            SELECT count(*)
            FROM information_schema.tables
            WHERE table_schema = 'public'
              AND table_name IN (
                  'assets',
                  'inventory_components',
                  'software_instances',
                  'findings',
                  'org_cve_records',
                  'fix_records'
              )
            """;

    private final JdbcTemplate platformJdbcTemplate;
    private final boolean enabled;

    public DatabaseResetCompatibilityGuardService(
            @Qualifier("platformJdbcTemplate") JdbcTemplate platformJdbcTemplate,
            @Value("${app.tenancy.fail-on-legacy-database:true}") boolean enabled
    ) {
        this.platformJdbcTemplate = platformJdbcTemplate;
        this.enabled = enabled;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void verifyResetLineCompatibility() {
        if (!enabled) {
            return;
        }
        if (legacyFlywayHistoryCount() > 0) {
            throw new IllegalStateException(
                    "Unsupported legacy Flyway history detected. This reset-line build only supports fresh platform/tenant schema databases."
            );
        }
        if (legacyPublicTenantTableCount() > 0) {
            throw new IllegalStateException(
                    "Unsupported shared-schema tenant tables detected in the public schema. Recreate the database from the postgres_reset baseline."
            );
        }
    }

    int legacyFlywayHistoryCount() {
        List<String> flywaySchemas = platformJdbcTemplate.queryForList("""
                SELECT table_schema
                FROM information_schema.tables
                WHERE table_name = 'flyway_schema_history'
                ORDER BY CASE WHEN table_schema = 'tenant_default' THEN 0 ELSE 1 END, table_schema
                """, String.class);
        if (flywaySchemas.isEmpty()) {
            return 0;
        }
        String rawSchemaName = flywaySchemas.get(0);
        if (rawSchemaName != null && rawSchemaName.contains(",")) {
            // Flyway currently reports the configured multi-schema descriptor here
            // (for example "tenant_default,platform"), which is not directly
            // queryable as a concrete schema. In that configuration we rely on the
            // public-schema table guard below to detect unsupported legacy resets.
            return 0;
        }
        String historySchema = quoteIdentifier(primarySchemaName(rawSchemaName));
        Integer legacyRows = platformJdbcTemplate.queryForObject("""
                SELECT count(*)
                FROM %s.flyway_schema_history
                WHERE version ~ '^[0-9]+$'
                AND CAST(version AS integer) >= 1000
                """.formatted(historySchema), Integer.class);
        return legacyRows == null ? 0 : legacyRows;
    }

    int legacyPublicTenantTableCount() {
        Integer count = platformJdbcTemplate.queryForObject(LEGACY_PUBLIC_TABLES_SQL, Integer.class);
        return count == null ? 0 : count;
    }

    private String quoteIdentifier(String schemaName) {
        if (schemaName == null || !schemaName.matches("[A-Za-z0-9_]+")) {
            throw new IllegalStateException("Unexpected Flyway schema name: " + schemaName);
        }
        return "\"" + schemaName + "\"";
    }

    private String primarySchemaName(String rawSchemaName) {
        if (rawSchemaName == null) {
            return null;
        }
        String normalized = rawSchemaName.trim();
        int commaIndex = normalized.indexOf(',');
        if (commaIndex >= 0) {
            normalized = normalized.substring(0, commaIndex).trim();
        }
        return normalized;
    }
}
