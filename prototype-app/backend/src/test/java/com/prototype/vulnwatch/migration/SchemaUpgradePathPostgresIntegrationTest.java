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
import org.flywaydb.core.api.MigrationVersion;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class SchemaUpgradePathPostgresIntegrationTest {

    private static final String CURRENT_SCHEMA_VERSION = "47";
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("schema_upgrade_path");

    @Test
    void canApplyResetBaselineWithoutHistoricalMigrations() throws Exception {
        Flyway flyway = configuredFlyway(null);
        flyway.migrate();

        assertNotNull(flyway.info().current());
        assertEquals(CURRENT_SCHEMA_VERSION, flyway.info().current().getVersion().getVersion());
        assertEquals(0, flyway.info().pending().length);
        assertEquals(0, failedCount());
        assertEquals(1, historyCount("1"));
    }

    private Flyway configuredFlyway(MigrationVersion target) {
        var config = Flyway.configure()
                .dataSource(DATABASE.url(), DATABASE.username(), DATABASE.password())
                .defaultSchema("public")
                .locations("filesystem:src/main/resources/db/migration/postgres_reset")
                .baselineOnMigrate(false)
                .baselineVersion("1")
                .validateOnMigrate(true)
                .outOfOrder(false);
        if (target != null) {
            config.target(target);
        }
        return config.load();
    }

    private int historyCount(String version) throws SQLException {
        return queryForInt("select count(*) from flyway_schema_history where version = '" + version + "' and success = true");
    }

    private int failedCount() throws SQLException {
        return queryForInt("select count(*) from flyway_schema_history where success = false");
    }

    private int queryForInt(String sql) throws SQLException {
        try (Connection connection = DriverManager.getConnection(DATABASE.url(), DATABASE.username(), DATABASE.password());
             Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(sql)) {
            resultSet.next();
            return resultSet.getInt(1);
        }
    }
}
