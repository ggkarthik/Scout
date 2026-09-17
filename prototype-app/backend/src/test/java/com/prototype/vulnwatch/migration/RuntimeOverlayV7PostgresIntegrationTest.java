package com.prototype.vulnwatch.migration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import com.prototype.vulnwatch.aisecurity.service.AiAgentExecutionRelationshipProjectionService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;

@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class RuntimeOverlayV7PostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("runtime_overlay_v7");
    private static final UUID TENANT_ID = UUID.fromString("e5fe0d29-1d64-4175-8ce6-c34f42b214cc");

    @Test
    void v7TenantServesAnEmptyRuntimeOverlayWithoutV8Indexes() throws Exception {
        Flyway.configure().dataSource(DATABASE.url(), DATABASE.username(), DATABASE.password())
                .defaultSchema("public").locations("filesystem:src/main/resources/db/migration/postgres_reset")
                .load().migrate();
        Flyway tenant = Flyway.configure().dataSource(DATABASE.url(), DATABASE.username(), DATABASE.password())
                .schemas("tenant_default").defaultSchema("tenant_default").table("tenant_schema_history")
                .locations("filesystem:src/main/resources/db/migration/tenant")
                .placeholders(Map.of("tenantId", TENANT_ID.toString(), "tenantSchema", "tenant_default"))
                .target(MigrationVersion.fromVersion("7")).load();
        tenant.migrate();
        assertEquals("7", tenant.info().current().getVersion().getVersion());

        try (Connection connection = DriverManager.getConnection(DATABASE.url(), DATABASE.username(), DATABASE.password())) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("set search_path to tenant_default,platform,public");
                statement.execute("select set_config('app.current_tenant_id','" + TENANT_ID + "',false)");
            }
            var service = new AiAgentExecutionRelationshipProjectionService(
                    new NamedParameterJdbcTemplate(new SingleConnectionDataSource(connection, true)));
            var overlay = service.aggregate(TENANT_ID, UUID.randomUUID(), Instant.now().minusSeconds(3600), Instant.now());
            assertEquals("AVAILABLE", overlay.status());
            assertEquals(0, overlay.executionCount());
            assertFalse(overlay.truncated());
        }
    }
}
