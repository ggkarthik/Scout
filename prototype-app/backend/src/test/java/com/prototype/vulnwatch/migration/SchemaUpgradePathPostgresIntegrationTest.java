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

    private static final String CURRENT_SCHEMA_VERSION = "92";
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("schema_upgrade_path");
    private static final LocalPostgresTestDatabase.DatabaseConfig UPGRADE_DATABASE =
            LocalPostgresTestDatabase.provision("schema_upgrade_phase1_path");

    @Test
    void canApplyResetBaselineWithoutHistoricalMigrations() throws Exception {
        Flyway flyway = configuredFlyway(null);
        flyway.migrate();

        assertNotNull(flyway.info().current());
        assertEquals(CURRENT_SCHEMA_VERSION, flyway.info().current().getVersion().getVersion());
        assertEquals(0, flyway.info().pending().length);
        assertEquals(0, failedCount());
        assertEquals(1, historyCount("1"));
        assertPhase1Catalog(DATABASE);
    }

    @Test
    void prePhase1DatabaseUpgradesToTheSameSeventySixEntryGovernedCatalog() throws Exception {
        configuredFlyway(UPGRADE_DATABASE, MigrationVersion.fromVersion("74")).migrate();
        configuredFlyway(UPGRADE_DATABASE, null).migrate();

        assertPhase1Catalog(UPGRADE_DATABASE);
    }

    private Flyway configuredFlyway(MigrationVersion target) {
        return configuredFlyway(DATABASE, target);
    }

    private Flyway configuredFlyway(LocalPostgresTestDatabase.DatabaseConfig database, MigrationVersion target) {
        var config = Flyway.configure()
                .dataSource(database.url(), database.username(), database.password())
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
        return queryForInt(DATABASE, sql);
    }

    private void assertPhase1Catalog(LocalPostgresTestDatabase.DatabaseConfig database) throws SQLException {
        assertEquals(76, queryForInt(database, "select count(*) from platform.ai_grid_policy_distribution d join platform.ai_grid_policy_versions p on p.policy_id=d.policy_id and p.version='1.0.0' where p.release_family='AGCF_PHASE_1'"));
        assertEquals(38, queryForInt(database, "select count(*) from platform.ai_grid_policy_versions where release_family='AGCF_PHASE_1' and provider='AWS'"));
        assertEquals(32, queryForInt(database, "select count(*) from platform.ai_grid_policy_versions where release_family='AGCF_PHASE_1' and provider='AZURE'"));
        assertEquals(6, queryForInt(database, "select count(*) from platform.ai_grid_policy_versions where release_family='AGCF_PHASE_1' and provider='MULTI_CLOUD'"));
        assertEquals(26, queryForInt(database, "select count(*) from platform.ai_grid_policy_distribution d join platform.ai_grid_policy_versions p on p.policy_id=d.policy_id and p.release_family='AGCF_PHASE_1' where d.default_selection='REQUIRED'"));
        assertEquals(24, queryForInt(database, "select count(*) from platform.ai_grid_policy_distribution d join platform.ai_grid_policy_versions p on p.policy_id=d.policy_id and p.release_family='AGCF_PHASE_1' where d.default_selection='ENABLED'"));
        assertEquals(26, queryForInt(database, "select count(*) from platform.ai_grid_policy_distribution d join platform.ai_grid_policy_versions p on p.policy_id=d.policy_id and p.release_family='AGCF_PHASE_1' where d.default_selection='DISABLED'"));
        assertEquals(76, queryForInt(database, "select count(*) from platform.ai_grid_policy_distribution d join platform.ai_grid_policy_versions p on p.policy_id=d.policy_id and p.release_family='AGCF_PHASE_1' where p.lifecycle='PUBLISHED' and d.rollout_stage='GENERAL_AVAILABILITY' and d.available=true"));
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
