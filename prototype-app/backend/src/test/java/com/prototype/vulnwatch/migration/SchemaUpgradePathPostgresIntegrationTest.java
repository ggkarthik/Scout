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
        assertPhase1Catalog(DATABASE);
    }

    @Test
    private Flyway configuredFlyway() {
        var config = Flyway.configure()
                .dataSource(DATABASE.url(), DATABASE.username(), DATABASE.password())
                .defaultSchema("public")
                .locations("filesystem:src/main/resources/db/migration/postgres_reset")
                .baselineOnMigrate(false)
                .baselineVersion("1")
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

    private void assertPhase1Catalog(LocalPostgresTestDatabase.DatabaseConfig database) throws SQLException {
        assertEquals(2, queryForInt(database, """
                select count(*) from information_schema.columns
                 where table_schema = 'platform' and table_name = 'ai_grid_policy_distribution'
                   and column_name in ('approved_package_digest', 'release_decision_id')
                """));
        assertEquals(76, queryForInt(database, "select count(*) from platform.ai_grid_policy_distribution d join platform.ai_grid_policy_versions p on p.policy_id=d.policy_id and p.version='1.0.0' where p.release_family='AGCF_PHASE_1'"));
        assertEquals(38, queryForInt(database, "select count(*) from platform.ai_grid_policy_versions where release_family='AGCF_PHASE_1' and provider='AWS'"));
        assertEquals(32, queryForInt(database, "select count(*) from platform.ai_grid_policy_versions where release_family='AGCF_PHASE_1' and provider='AZURE'"));
        assertEquals(6, queryForInt(database, "select count(*) from platform.ai_grid_policy_versions where release_family='AGCF_PHASE_1' and provider='MULTI_CLOUD'"));
        assertEquals(26, queryForInt(database, "select count(*) from platform.ai_grid_policy_distribution d join platform.ai_grid_policy_versions p on p.policy_id=d.policy_id and p.release_family='AGCF_PHASE_1' where d.default_selection='REQUIRED'"));
        assertEquals(24, queryForInt(database, "select count(*) from platform.ai_grid_policy_distribution d join platform.ai_grid_policy_versions p on p.policy_id=d.policy_id and p.release_family='AGCF_PHASE_1' where d.default_selection='ENABLED'"));
        assertEquals(26, queryForInt(database, "select count(*) from platform.ai_grid_policy_distribution d join platform.ai_grid_policy_versions p on p.policy_id=d.policy_id and p.release_family='AGCF_PHASE_1' where d.default_selection='DISABLED'"));
        assertEquals(76, queryForInt(database, "select count(*) from platform.ai_grid_policy_distribution d join platform.ai_grid_policy_versions p on p.policy_id=d.policy_id and p.release_family='AGCF_PHASE_1' where p.lifecycle='VALIDATED' and d.rollout_stage='PAUSED' and d.available=false"));
        assertEquals(1, queryForInt(database, "select count(*) from platform.ai_grid_policy_versions where policy_id='AGCF-AWS-033' and required_facts_json->0->>'valueType'='STRING'"));
        assertEquals(6, queryForInt(database, "select count(*) from platform.ai_grid_policy_versions where policy_id like 'AGCF-XSP-%' and required_facts_json='[]'::jsonb"));
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
