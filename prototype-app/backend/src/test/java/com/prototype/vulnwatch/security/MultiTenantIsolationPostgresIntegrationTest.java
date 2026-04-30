package com.prototype.vulnwatch.security;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@SpringBootTest(properties = {
        "app.security.api-key=test-api-key",
        "app.tenancy.require-tenant-context=true",
        "app.tenancy.allow-header-tenant-selection=false",
        "app.correlation.backfill-targets-on-startup=false"
})
@ActiveProfiles("postgres")
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class MultiTenantIsolationPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("multi_tenant_isolation");
    private static final String RLS_USER = "vulnwatch_isolation_reader";
    private static final String RLS_PASSWORD = "vulnwatch-isolation-test";

    private final UUID customerA = UUID.fromString("aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa");
    private final UUID customerB = UUID.fromString("bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb");

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        registry.add("DB_URL", DATABASE::url);
        registry.add("DB_USERNAME", DATABASE::username);
        registry.add("DB_PASSWORD", DATABASE::password);
    }

    @BeforeEach
    void seedTenantScopedRows() {
        jdbcTemplate.update("""
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'vulnwatch_isolation_reader') THEN
                        CREATE ROLE vulnwatch_isolation_reader LOGIN PASSWORD 'vulnwatch-isolation-test';
                    END IF;
                END
                $$;
                """);
        jdbcTemplate.update("""
                INSERT INTO tenants (id, created_at, name, slug, status)
                VALUES (?, now(), 'Customer A', 'customer-a', 'ACTIVE'),
                       (?, now(), 'Customer B', 'customer-b', 'ACTIVE')
                ON CONFLICT (id) DO NOTHING
                """, customerA, customerB);
        jdbcTemplate.update("DELETE FROM assets WHERE tenant_id IN (?, ?)", customerA, customerB);
        setTenant(customerA);
        insertAsset(customerA, "asset-a");
        setTenant(customerB);
        insertAsset(customerB, "asset-b");
        jdbcTemplate.update("GRANT USAGE ON SCHEMA public TO " + RLS_USER);
        jdbcTemplate.update("GRANT SELECT ON assets TO " + RLS_USER);
    }

    @Test
    void tenantScopedRlsOnlyReturnsCurrentTenantRows() throws Exception {
        assertEquals(1, countAssetsAsRestrictedRole(customerA));
        assertEquals("asset-a", firstAssetIdentifierAsRestrictedRole(customerA));

        assertEquals(1, countAssetsAsRestrictedRole(customerB));
        assertEquals("asset-b", firstAssetIdentifierAsRestrictedRole(customerB));
    }

    @Test
    void missingTenantContextMatchesNoTenantRowsWhenSentinelIsSet() throws Exception {
        assertEquals(0, countAssetsAsRestrictedRole(new UUID(0, 0)));
    }

    private void setTenant(UUID tenantId) {
        jdbcTemplate.queryForObject("SELECT set_config('app.current_tenant_id', ?, false)", String.class, tenantId.toString());
    }

    private void insertAsset(UUID tenantId, String identifier) {
        jdbcTemplate.update("""
                INSERT INTO assets (
                    id, tenant_id, identifier, name, type, business_criticality,
                    state, created_at
                )
                VALUES (?, ?, ?, ?, 'APPLICATION', 'MEDIUM', 'ACTIVE', now())
                ON CONFLICT (tenant_id, identifier) DO NOTHING
                """, UUID.randomUUID(), tenantId, identifier, identifier);
    }

    private int countAssetsAsRestrictedRole(UUID tenantId) throws Exception {
        try (Connection connection = DriverManager.getConnection(DATABASE.url(), RLS_USER, RLS_PASSWORD);
             Statement statement = connection.createStatement()) {
            statement.execute("SELECT set_config('app.current_tenant_id', '" + tenantId + "', false)");
            try (ResultSet resultSet = statement.executeQuery("SELECT count(*) FROM assets")) {
                resultSet.next();
                return resultSet.getInt(1);
            }
        }
    }

    private String firstAssetIdentifierAsRestrictedRole(UUID tenantId) throws Exception {
        try (Connection connection = DriverManager.getConnection(DATABASE.url(), RLS_USER, RLS_PASSWORD);
             Statement statement = connection.createStatement()) {
            statement.execute("SELECT set_config('app.current_tenant_id', '" + tenantId + "', false)");
            try (ResultSet resultSet = statement.executeQuery("SELECT identifier FROM assets ORDER BY identifier LIMIT 1")) {
                resultSet.next();
                return resultSet.getString(1);
            }
        }
    }
}
