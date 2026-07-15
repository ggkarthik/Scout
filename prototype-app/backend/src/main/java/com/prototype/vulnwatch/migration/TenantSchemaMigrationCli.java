package com.prototype.vulnwatch.migration;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;

/** Minimal migration entry point that intentionally does not initialize Spring or JPA. */
public final class TenantSchemaMigrationCli {

    private static final int TARGET_VERSION = 44;

    private static final Pattern UUID_VALUE = Pattern.compile(
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}");

    private TenantSchemaMigrationCli() {
    }

    public static void main(String[] args) throws Exception {
        String url = required("DB_URL");
        String username = required("DB_USERNAME");
        String password = required("DB_PASSWORD");

        Flyway.configure()
                .dataSource(url, username, password)
                .schemas("public")
                .defaultSchema("public")
                .table("flyway_schema_history")
                .locations("classpath:db/migration/postgres_reset")
                .baselineOnMigrate(false)
                .validateOnMigrate(true)
                .outOfOrder(false)
                .load()
                .migrate();

        try (Connection lockConnection = DriverManager.getConnection(url, username, password)) {
            if (!acquireLock(lockConnection)) {
                throw new IllegalStateException("Unable to acquire tenant migration advisory lock");
            }
            try {
                List<TenantSchema> tenants = tenants(lockConnection);
                for (TenantSchema tenant : tenants) {
                    migrateTenant(url, username, password, tenant);
                    String checksum = fingerprint(lockConnection, tenant.schemaName());
                    markCurrent(lockConnection, tenant, checksum);
                    System.out.printf(
                            "tenant_migration_status=current tenant_id=%s schema=%s version=%d checksum=%s%n",
                            tenant.tenantId(), tenant.schemaName(), TARGET_VERSION, checksum);
                }
                System.out.printf("tenant_migration_report=complete target_version=%d tenant_count=%d%n",
                        TARGET_VERSION, tenants.size());
            } finally {
                try (PreparedStatement statement = lockConnection.prepareStatement(
                        "select pg_advisory_unlock(hashtext('scout-tenant-schema-migrator'))")) {
                    statement.execute();
                }
            }
        }
    }

    private static void migrateTenant(String url, String username, String password, TenantSchema tenant) {
        Flyway.configure()
                .dataSource(url, username, password)
                .schemas(tenant.schemaName())
                .defaultSchema(tenant.schemaName())
                .table("tenant_schema_history")
                .locations("classpath:db/migration/tenant")
                .baselineOnMigrate(true)
                .baselineVersion(MigrationVersion.fromVersion("41"))
                .baselineDescription("legacy tenant schema baseline")
                .placeholders(java.util.Map.of(
                        "tenantId", tenant.tenantId().toString(),
                        "tenantSchema", tenant.schemaName()))
                .validateOnMigrate(true)
                .outOfOrder(false)
                .initSql("SET statement_timeout = '5min'")
                .load()
                .migrate();
    }

    private static boolean acquireLock(Connection connection) throws Exception {
        Instant deadline = Instant.now().plusSeconds(30);
        while (Instant.now().isBefore(deadline)) {
            try (PreparedStatement statement = connection.prepareStatement(
                    "select pg_try_advisory_lock(hashtext('scout-tenant-schema-migrator'))");
                 ResultSet result = statement.executeQuery()) {
                if (result.next() && result.getBoolean(1)) {
                    return true;
                }
            }
            Thread.sleep(250);
        }
        return false;
    }

    private static List<TenantSchema> tenants(Connection connection) throws Exception {
        List<TenantSchema> tenants = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement(
                "select id, schema_name from platform.tenants order by created_at, schema_name");
             ResultSet result = statement.executeQuery()) {
            while (result.next()) {
                tenants.add(new TenantSchema(result.getObject(1, UUID.class), result.getString(2)));
            }
        }
        return tenants;
    }

    private static void markCurrent(Connection connection, TenantSchema tenant, String checksum) throws Exception {
        try (PreparedStatement statement = connection.prepareStatement("""
                insert into platform.tenant_schema_versions (
                    tenant_id, schema_name, current_version, target_version, status,
                    structural_checksum, migration_started_at, migration_completed_at,
                    last_successful_version, failure_code, failure_message, updated_at, migration_run_id
                ) values (?, ?, 44, 44, 'CURRENT', ?, now(), now(), 44, null, null, now(), ?)
                on conflict (tenant_id) do update set
                    schema_name = excluded.schema_name,
                    current_version = 44,
                    target_version = 44,
                    status = 'CURRENT',
                    structural_checksum = excluded.structural_checksum,
                    migration_completed_at = now(),
                    last_successful_version = 44,
                    failure_code = null,
                    failure_message = null,
                    updated_at = now(),
                    migration_run_id = excluded.migration_run_id
                """)) {
            statement.setObject(1, tenant.tenantId());
            statement.setString(2, tenant.schemaName());
            statement.setString(3, checksum);
            statement.setObject(4, UUID.randomUUID());
            statement.executeUpdate();
        }
    }

    private static String fingerprint(Connection connection, String schemaName) throws Exception {
        String sql = """
                with objects as (
                    select concat_ws('|', 'column', c.table_name, c.ordinal_position::text, c.column_name,
                           c.data_type, coalesce(c.character_maximum_length::text, ''),
                           c.is_nullable, coalesce(c.column_default, ''))::text as definition
                    from information_schema.columns c
                    where c.table_schema = ? and c.table_name not in ('tenant_schema_history', 'flyway_schema_history')
                    union all
                    select concat_ws('|', 'constraint', cl.relname::text, con.contype::text,
                           pg_get_constraintdef(con.oid))::text
                    from pg_constraint con
                    join pg_class cl on cl.oid = con.conrelid
                    join pg_namespace n on n.oid = cl.relnamespace
                    where n.nspname = ?
                    union all
                    select concat_ws('|', 'index', tab.relname::text, pg_get_indexdef(idx.oid))::text
                    from pg_index i
                    join pg_class idx on idx.oid = i.indexrelid
                    join pg_class tab on tab.oid = i.indrelid
                    join pg_namespace n on n.oid = tab.relnamespace
                    where n.nspname = ?
                    union all
                    select concat_ws('|', 'sequence', sequence_name, data_type, increment,
                           minimum_value, maximum_value, cycle_option)::text
                    from information_schema.sequences where sequence_schema = ?
                    union all
                    select concat_ws('|', 'rls', c.relname::text, c.relrowsecurity::text,
                           c.relforcerowsecurity::text, coalesce(p.polname::text, ''),
                           coalesce(pg_get_expr(p.polqual, p.polrelid), ''),
                           coalesce(pg_get_expr(p.polwithcheck, p.polrelid), ''))::text
                    from pg_class c
                    join pg_namespace n on n.oid = c.relnamespace
                    left join pg_policy p on p.polrelid = c.oid
                    where n.nspname = ? and c.relkind in ('r', 'p')
                      and c.relname not in ('tenant_schema_history', 'flyway_schema_history')
                )
                select definition from objects order by definition
                """;
        List<String> definitions = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            for (int index = 1; index <= 5; index++) {
                statement.setString(index, schemaName);
            }
            try (ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    definitions.add(result.getString(1));
                }
            }
        }
        String normalized = String.join("\n", definitions).replace(schemaName, "<tenant_schema>");
        normalized = UUID_VALUE.matcher(normalized).replaceAll("<tenant_id>");
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(normalized.getBytes(StandardCharsets.UTF_8)));
    }

    private static String required(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " is required");
        }
        return value;
    }

    private record TenantSchema(UUID tenantId, String schemaName) {
    }
}
