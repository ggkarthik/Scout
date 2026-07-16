package com.prototype.vulnwatch.migration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class ProductionBootstrapCliPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("production_bootstrap_cli");

    @Test
    void cleanDatabaseBootstrapsAndRerunsIdempotently() throws Exception {
        withBootstrapProperties(() -> {
            ProductionBootstrapCli.main(new String[0]);
            ProductionBootstrapCli.main(new String[0]);
        });

        assertEquals(44, queryInt("""
                select max(version::integer)
                from public.flyway_schema_history
                where version ~ '^[0-9]+$' and success
                """));
        assertEquals(1, queryInt("""
                select count(*)
                from platform.tenants
                where name = 'Default Workspace'
                  and schema_name = 'tenant_default'
                  and status = 'ACTIVE'
                """));
        assertEquals(1, queryInt("""
                select count(*)
                from platform.tenant_schema_versions
                where schema_name = 'tenant_default'
                  and status = 'CURRENT'
                  and current_version = 44
                  and last_successful_version = 44
                  and nullif(structural_checksum, '') is not null
                """));
        assertEquals(1, queryInt("""
                select count(*)
                from tenant_default.tenant_schema_history
                where version = '44' and success
                """));
        assertTrue(queryInt("""
                select count(*)
                from pg_roles
                where rolname = 'scout_runtime_bootstrap_it'
                  and rolcanlogin
                  and not rolsuper
                  and not rolcreatedb
                  and not rolcreaterole
                  and not rolbypassrls
                """) >= 1);
    }

    private void withBootstrapProperties(ThrowingRunnable runnable) throws Exception {
        set("DB_URL", DATABASE.url());
        set("DB_USERNAME", DATABASE.username());
        set("DB_PASSWORD", DATABASE.password());
        set("RUNTIME_DB_USERNAME", "scout_runtime_bootstrap_it");
        set("RUNTIME_DB_PASSWORD", "scout-runtime-bootstrap-it-" + UUID.randomUUID());
        try {
            runnable.run();
        } finally {
            clear("DB_URL");
            clear("DB_USERNAME");
            clear("DB_PASSWORD");
            clear("RUNTIME_DB_USERNAME");
            clear("RUNTIME_DB_PASSWORD");
        }
    }

    private int queryInt(String sql) throws Exception {
        try (Connection connection = DriverManager.getConnection(DATABASE.url(), DATABASE.username(), DATABASE.password());
             Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(sql)) {
            resultSet.next();
            return resultSet.getInt(1);
        }
    }

    private void set(String key, String value) {
        if (value == null) {
            System.clearProperty(key);
        } else {
            System.setProperty(key, value);
        }
    }

    private void clear(String key) {
        System.clearProperty(key);
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }
}
