package com.prototype.vulnwatch.migration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class SchemaUpgradePathPostgresIntegrationTest {

    private static final String CURRENT_SCHEMA_VERSION = "1";
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("schema_upgrade_path");

    @Test
    void canApplyResetBaselineWithoutHistoricalMigrations() throws Exception {
        Flyway flyway = configuredFlyway();
        flyway.migrate();

        assertNotNull(flyway.info().current());
        assertEquals(CURRENT_SCHEMA_VERSION, flyway.info().current().getVersion().getVersion());
        assertEquals(0, flyway.info().pending().length);
        assertEquals(0, failedCount());
        assertEquals(1, historyCount("1"));
        assertEquals(180, queryForInt(DATABASE, "select count(*) from platform.ai_grid_policy_versions"));
        assertEquals(1, queryForInt(DATABASE, "select count(*) from information_schema.schemata where schema_name='tenant_default'"));
    }

    @Test
    void tenantDefaultCanBeMigratedFromTheEmptyPlatformBaseline() throws Exception {
        configuredFlyway().migrate();
        Flyway tenant = Flyway.configure()
                .dataSource(DATABASE.url(), DATABASE.username(), DATABASE.password())
                .schemas("tenant_default")
                .defaultSchema("tenant_default")
                .table("tenant_schema_history")
                .locations("filesystem:src/main/resources/db/migration/tenant")
                .placeholders(java.util.Map.of("tenantSchema", "tenant_default"))
                .validateOnMigrate(true)
                .outOfOrder(false)
                .load();
        tenant.migrate();
        assertEquals("1", tenant.info().current().getVersion().getVersion());
    }

    private Flyway configuredFlyway() {
        var config = Flyway.configure()
                .dataSource(DATABASE.url(), DATABASE.username(), DATABASE.password())
                .defaultSchema("public")
                .locations("filesystem:src/main/resources/db/migration/postgres_reset")
                .validateOnMigrate(true)
                .outOfOrder(false);
        return config.load();
    }

    private int historyCount(String version) throws SQLException {
        return queryForInt("select count(*) from flyway_schema_history where version = '" + version + "' and success = true");
    }

    private int failedCount() throws SQLException {
        return queryForInt("select count(*) from flyway_schema_history where success = false");
    }

    private int queryForInt(String sql) throws SQLException {
        return queryForInt(DATABASE, sql);
    }

    private int queryForInt(LocalPostgresTestDatabase.DatabaseConfig database, String sql) throws SQLException {
        try (Connection connection = DriverManager.getConnection(database.url(), database.username(), database.password());
             Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(sql)) {
            resultSet.next();
            return resultSet.getInt(1);
        }
    }

}
