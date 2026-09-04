package com.prototype.vulnwatch.migration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
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
    void provisionedTenantReachesPackagedTargetAndHasRls() {
        Tenant tenant = tenantService.createTenant("Drift Customer", "drift-customer", "pilot", null);
        tenantSchemaMigrationService.provisionNewTenant(tenant);
        String schemaName = tenant.getSchemaName();

        Integer version = platformJdbcTemplate.queryForObject("""
                select current_version from platform.tenant_schema_versions where tenant_id = ?
                """, Integer.class, tenant.getId());
        Integer target = platformJdbcTemplate.queryForObject("""
                select target_version from platform.tenant_schema_versions where tenant_id = ? and status = 'CURRENT'
                """, Integer.class, tenant.getId());
        Integer incompleteRls = platformJdbcTemplate.queryForObject("""
                select count(*)
                from pg_class c
                join pg_namespace n on n.oid = c.relnamespace
                where n.nspname = ? and c.relkind in ('r', 'p')
                  and c.relname not in ('tenant_schema_history', 'flyway_schema_history', 'demo_requests')
                  and (not c.relrowsecurity or not c.relforcerowsecurity
                       or not exists (select 1 from pg_policy p where p.polrelid = c.oid and p.polname = 'tenant_isolation'))
                """, Integer.class, schemaName);
        assertEquals(PackagedMigrationCatalog.resolve().tenantTarget(), version);
        assertEquals(PackagedMigrationCatalog.resolve().tenantTarget(), target);
        assertEquals(0, incompleteRls);
    }
}
