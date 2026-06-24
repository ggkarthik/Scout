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
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
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
    private static final String RUNTIME_ROLE = "rls_runtime_role";

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
        prepareRuntimeRole();

        try (Connection connection = DriverManager.getConnection(DATABASE.url(), DATABASE.username(), DATABASE.password());
             Statement statement = connection.createStatement()) {
            statement.execute("SET ROLE " + RUNTIME_ROLE);
            statement.execute("SELECT set_config('app.current_tenant_id', '" + defaultTenant.getId() + "', FALSE)");

            statement.execute(assetInsertSql(defaultTenant.getId(), "rls-ok"));

            SQLException crossTenant = assertThrows(
                    SQLException.class,
                    () -> statement.execute(assetInsertSql(otherTenant.getId(), "rls-cross-tenant"))
            );
            assertEquals("42501", crossTenant.getSQLState());

            statement.execute("RESET app.current_tenant_id");
            SQLException missingContext = assertThrows(
                    SQLException.class,
                    () -> statement.execute(assetInsertSql(defaultTenant.getId(), "rls-missing-context"))
            );
            assertEquals("42501", missingContext.getSQLState());
        }
    }

    private void prepareRuntimeRole() {
        platformJdbcTemplate.execute("DROP ROLE IF EXISTS " + RUNTIME_ROLE);
        platformJdbcTemplate.execute("CREATE ROLE " + RUNTIME_ROLE);
        platformJdbcTemplate.execute("GRANT USAGE ON SCHEMA platform, tenant_default TO " + RUNTIME_ROLE);
        platformJdbcTemplate.execute("GRANT SELECT, REFERENCES ON ALL TABLES IN SCHEMA platform TO " + RUNTIME_ROLE);
        platformJdbcTemplate.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA tenant_default TO " + RUNTIME_ROLE);
        platformJdbcTemplate.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA tenant_default TO " + RUNTIME_ROLE);
    }

    private String assetInsertSql(UUID tenantId, String identifier) {
        Instant now = Instant.now();
        return """
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
                    '%s',
                    'MEDIUM',
                    '%s',
                    '%s',
                    '%s',
                    'ACTIVE',
                    'APPLICATION',
                    '%s'
                )
                """.formatted(UUID.randomUUID(), now, identifier, identifier, tenantId);
    }
}
