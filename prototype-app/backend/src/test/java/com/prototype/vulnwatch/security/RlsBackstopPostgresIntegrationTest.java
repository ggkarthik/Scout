package com.prototype.vulnwatch.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@PostgresIntegrationTest
class RlsBackstopPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("rls_backstop");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired
    private JdbcTemplate platformJdbcTemplate;

    @Autowired
    private TenantService tenantService;

    @Test
    void nonSuperuserRuntimeRoleCannotBypassTenantRls() throws Exception {
        Tenant defaultTenant = tenantService.getDefaultTenant();
        Tenant otherTenant = tenantService.createTenant("RLS Other", "rls-other", "enterprise", null);
        enableRlsForAssets();
        prepareRuntimeRole();

        try (Connection connection = DriverManager.getConnection(DATABASE.url(), DATABASE.username(), DATABASE.password());
             Statement statement = connection.createStatement()) {
            statement.execute("SET ROLE rls_runtime_role");
            setCurrentTenant(connection, defaultTenant.getId());

            insertAsset(connection, defaultTenant.getId(), "rls-ok");

            SQLException crossTenant = assertThrows(
                    SQLException.class,
                    () -> insertAsset(connection, otherTenant.getId(), "rls-cross-tenant")
            );
            assertEquals("42501", crossTenant.getSQLState());

            statement.execute("RESET app.current_tenant_id");
            SQLException missingContext = assertThrows(
                    SQLException.class,
                    () -> insertAsset(connection, defaultTenant.getId(), "rls-missing-context")
            );
            assertEquals("42501", missingContext.getSQLState());
        }
    }

    private void enableRlsForAssets() {
        platformJdbcTemplate.execute("ALTER TABLE tenant_default.assets ENABLE ROW LEVEL SECURITY");
        platformJdbcTemplate.execute("ALTER TABLE tenant_default.assets FORCE ROW LEVEL SECURITY");
        platformJdbcTemplate.execute("DROP POLICY IF EXISTS tenant_isolation ON tenant_default.assets");
        platformJdbcTemplate.execute("""
                CREATE POLICY tenant_isolation ON tenant_default.assets
                USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
                WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
                """);
    }

    private void prepareRuntimeRole() {
        platformJdbcTemplate.execute("DROP ROLE IF EXISTS rls_runtime_role");
        platformJdbcTemplate.execute("CREATE ROLE rls_runtime_role");
        platformJdbcTemplate.execute("GRANT USAGE ON SCHEMA platform, tenant_default TO rls_runtime_role");
        platformJdbcTemplate.execute("GRANT SELECT, REFERENCES ON ALL TABLES IN SCHEMA platform TO rls_runtime_role");
        platformJdbcTemplate.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA tenant_default TO rls_runtime_role");
        platformJdbcTemplate.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA tenant_default TO rls_runtime_role");
    }

    private void setCurrentTenant(Connection connection, UUID tenantId) throws SQLException {
        try (PreparedStatement statement =
                     connection.prepareStatement("SELECT set_config('app.current_tenant_id', ?, FALSE)")) {
            statement.setString(1, tenantId.toString());
            statement.execute();
        }
    }

    private void insertAsset(Connection connection, UUID tenantId, String identifier) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO tenant_default.assets (
                    id,
                    business_criticality,
                    created_at,
                    identifier,
                    name,
                    state,
                    type,
                    tenant_id
                ) VALUES (
                    ?,
                    'MEDIUM',
                    now(),
                    ?,
                    ?,
                    'ACTIVE',
                    'APPLICATION',
                    ?
                )
                """)) {
            statement.setObject(1, UUID.randomUUID());
            statement.setString(2, identifier);
            statement.setString(3, identifier);
            statement.setObject(4, tenantId);
            statement.execute();
        }
    }
}
