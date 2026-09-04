package com.prototype.vulnwatch.migration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@PostgresIntegrationTest
class SchemaMigrationStartupPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("schema_migration_startup");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired
    private Flyway flyway;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void contextStartupAppliesAllMigrationsOnFreshDatabase() {
        assertNotNull(flyway.info().current());
        String packagedTarget = Integer.toString(PackagedMigrationCatalog.resolve().platformTarget());
        assertEquals(packagedTarget, flyway.info().current().getVersion().getVersion());
        assertEquals(0, flyway.info().pending().length);

        Integer failed = jdbcTemplate.queryForObject(
                "select count(*) from public.flyway_schema_history where success = false",
                Integer.class
        );
        Integer latest = jdbcTemplate.queryForObject(
                "select count(*) from public.flyway_schema_history where version = ? and success = true",
                Integer.class, packagedTarget
        );

        assertEquals(0, failed);
        assertEquals(1, latest);
        assertEquals(54, jdbcTemplate.queryForObject(
                "select count(*) from platform.ai_grid_resource_family_definitions where lifecycle = 'ACTIVE'", Integer.class));
        assertEquals(34, jdbcTemplate.queryForObject(
                "select count(*) from platform.ai_grid_relationship_definitions where lifecycle = 'ACTIVE'", Integer.class));
        assertEquals(6, jdbcTemplate.queryForObject(
                "select count(*) from platform.ai_grid_correlation_versions where lifecycle = 'PUBLISHED'", Integer.class));
        assertEquals(76, jdbcTemplate.queryForObject(
                "select count(*) from platform.ai_grid_policy_versions where policy_id like 'AGCF-%' and release_family = 'AGCF_PHASE_1' and release_wave = 'PHASE_1'", Integer.class));
        assertEquals(1, jdbcTemplate.queryForObject(
                "select count(*) from platform.ai_grid_policy_migration_ledger", Integer.class));
    }
}
