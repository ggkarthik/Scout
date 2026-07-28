package com.prototype.vulnwatch.migration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@PostgresIntegrationTest
class TenantSchemaReconciliationPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("tenant_schema_reconciliation");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired
    private TenantService tenantService;

    @Autowired
    private TenantSchemaMigrationService tenantSchemaMigrationService;

    @Autowired
    @Qualifier("platformJdbcTemplate")
    private JdbcTemplate platformJdbcTemplate;

    @Test
    void reconciliationAddsDefaultSchemaColumnsMissingFromExistingTenantSchemas() throws IOException {
        Tenant tenant = tenantService.createTenant("Drift Customer", "drift-customer", "pilot", null);
        tenantSchemaMigrationService.provisionNewTenant(tenant);
        String schemaName = tenant.getSchemaName();

        Integer version = platformJdbcTemplate.queryForObject("""
                select current_version from platform.tenant_schema_versions where tenant_id = ?
                """, Integer.class, tenant.getId());
        String checksum = platformJdbcTemplate.queryForObject("""
                select structural_checksum from platform.tenant_schema_versions where tenant_id = ?
                """, String.class, tenant.getId());
        Integer incompleteRls = platformJdbcTemplate.queryForObject("""
                select count(*)
                from pg_class c
                join pg_namespace n on n.oid = c.relnamespace
                where n.nspname = ? and c.relkind in ('r', 'p')
                  and c.relname not in ('tenant_schema_history', 'flyway_schema_history', 'demo_requests')
                  and (not c.relrowsecurity or not c.relforcerowsecurity
                       or not exists (select 1 from pg_policy p where p.polrelid = c.oid and p.polname = 'tenant_isolation'))
                """, Integer.class, schemaName);
        Boolean demoRlsEnabled = platformJdbcTemplate.queryForObject("""
                select c.relrowsecurity or c.relforcerowsecurity
                from pg_class c join pg_namespace n on n.oid = c.relnamespace
                where n.nspname = ? and c.relname = 'demo_requests'
                """, Boolean.class, schemaName);
        Boolean auditAllowsPlatformEvents = platformJdbcTemplate.queryForObject("""
                select c.is_nullable = 'YES' and rel.relrowsecurity and rel.relforcerowsecurity
                from information_schema.columns c
                join pg_namespace n on n.nspname = c.table_schema
                join pg_class rel on rel.relnamespace = n.oid and rel.relname = c.table_name
                where c.table_schema = ? and c.table_name = 'audit_events' and c.column_name = 'tenant_id'
                """, Boolean.class, schemaName);

        assertEquals(45, version);
        assertNotNull(checksum);
        assertEquals(0, incompleteRls);
        assertEquals(false, demoRlsEnabled);
        assertEquals(true, auditAllowsPlatformEvents);

        platformJdbcTemplate.execute("ALTER TABLE tenant_default.assets ADD COLUMN reconciliation_probe text");
        assertColumnCount(schemaName, "assets", "reconciliation_probe", 0);

        platformJdbcTemplate.execute(reconciliationSql());

        assertColumnCount(schemaName, "assets", "reconciliation_probe", 1);
    }

    private String reconciliationSql() throws IOException {
        ClassPathResource resource = new ClassPathResource(
                "db/migration/postgres_reset/V28__tenant_schema_reconciliation.sql");
        return resource.getContentAsString(StandardCharsets.UTF_8);
    }

    private void assertColumnCount(String schemaName, String tableName, String columnName, int expected) {
        Integer count = platformJdbcTemplate.queryForObject("""
                select count(*)
                from information_schema.columns
                where table_schema = ?
                  and table_name = ?
                  and column_name = ?
                """, Integer.class, schemaName, tableName, columnName);
        assertEquals(expected, count);
    }
}
