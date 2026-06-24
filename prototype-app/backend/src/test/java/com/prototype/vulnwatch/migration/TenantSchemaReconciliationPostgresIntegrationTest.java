package com.prototype.vulnwatch.migration;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.prototype.vulnwatch.domain.Tenant;
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
    @Qualifier("platformJdbcTemplate")
    private JdbcTemplate platformJdbcTemplate;

    @Test
    void reconciliationAddsDefaultSchemaColumnsMissingFromExistingTenantSchemas() throws IOException {
        Tenant tenant = tenantService.createTenant("Drift Customer", "drift-customer", "pilot", null);
        String schemaName = tenant.getSchemaName();

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
