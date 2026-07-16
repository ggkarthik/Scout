package com.prototype.vulnwatch.migration;

import com.prototype.vulnwatch.service.TenantSchemaService;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;

/** Production-only bootstrap entry point. Does not initialize Spring or JPA. */
public final class ProductionBootstrapCli {

    private static final int TARGET_VERSION = 44;
    private static final String DEFAULT_TENANT_NAME = "Default Workspace";
    private static final String DEFAULT_TENANT_SLUG = "default-workspace";
    private static final String DEFAULT_TENANT_SCHEMA = "tenant_default";
    private static final String LOCK_NAME = "scout-production-bootstrap";
    private static final UUID DEFAULT_TENANT_ID = UUID.nameUUIDFromBytes(
            "scout-default-tenant".getBytes(StandardCharsets.UTF_8));
    private static final Pattern UUID_VALUE = Pattern.compile(
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}");

    private ProductionBootstrapCli() {
    }

    public static void main(String[] args) throws Exception {
        Config config = Config.fromEnvironment();
        UUID runId = UUID.randomUUID();
        Instant startedAt = Instant.now();
        List<Phase> phases = new ArrayList<>();
        boolean success = false;
        String failureCode = null;
        String failureMessage = null;
        try {
            try (Connection connection = DriverManager.getConnection(
                    config.dbUrl(), config.dbUsername(), config.dbPassword())) {
                acquireLock(connection);
                try {
                    if (config.reportOnly()) {
                        verifyControlPlane(connection, config.runtimeDbUsername());
                        phases.add(Phase.success("report_only_owner_verification", "complete"));
                    } else {
                        runPlatformMigrations(config);
                        phases.add(Phase.success("platform_migrations", "version=" + platformVersion(connection)));
                        TenantSchema defaultTenant = ensureDefaultTenant(connection);
                        phases.add(Phase.success("default_tenant_registration", defaultTenant.schemaName()));
                        migrateTenant(config, defaultTenant);
                        String templateChecksum = fingerprint(connection, defaultTenant.schemaName());
                        markCurrent(connection, defaultTenant, templateChecksum, runId);
                        phases.add(Phase.success("default_tenant_migration", "version=" + TARGET_VERSION));
                        BootstrapResult tenantResult = migrateExistingAndProvisioningTenants(
                                connection, config, defaultTenant, templateChecksum, runId);
                        phases.addAll(tenantResult.phases());
                        if (!tenantResult.success()) {
                            throw new BootstrapFailure("tenant_provisioning_failed", "Tenant provisioning failed");
                        }
                        provisionRuntimeRole(connection, config.runtimeDbUsername(), config.runtimeDbPassword());
                        phases.add(Phase.success("runtime_role_provisioning", config.runtimeDbUsername()));
                        verifyControlPlane(connection, config.runtimeDbUsername());
                        phases.add(Phase.success("owner_verification", "complete"));
                    }
                } finally {
                    releaseLock(connection);
                }
            }
            verifyRuntimeConnection(config);
            phases.add(Phase.success("runtime_verification", "complete"));
            success = true;
        } catch (BootstrapFailure ex) {
            failureCode = ex.code();
            failureMessage = sanitize(ex.getMessage());
            phases.add(Phase.failed(failureCode, failureMessage));
        } catch (Exception ex) {
            failureCode = "bootstrap_failed";
            failureMessage = sanitize(ex.getMessage());
            phases.add(Phase.failed(failureCode, failureMessage));
        }
        Instant completedAt = Instant.now();
        System.out.println(report(runId, startedAt, completedAt, success, failureCode, failureMessage, phases));
        if (!success) {
            System.exit(1);
        }
    }

    private static void runPlatformMigrations(Config config) {
        Flyway.configure()
                .dataSource(config.dbUrl(), config.dbUsername(), config.dbPassword())
                .schemas("public")
                .defaultSchema("public")
                .table("flyway_schema_history")
                .locations("classpath:db/migration/postgres_reset")
                .baselineOnMigrate(false)
                .validateOnMigrate(true)
                .outOfOrder(false)
                .load()
                .migrate();
    }

    private static TenantSchema ensureDefaultTenant(Connection connection) throws SQLException {
        try (PreparedStatement select = connection.prepareStatement("""
                select id, schema_name
                from platform.tenants
                where lower(name) = lower(?) or schema_name = ?
                order by case when schema_name = ? then 0 else 1 end, created_at
                limit 1
                """)) {
            select.setString(1, DEFAULT_TENANT_NAME);
            select.setString(2, DEFAULT_TENANT_SCHEMA);
            select.setString(3, DEFAULT_TENANT_SCHEMA);
            try (ResultSet result = select.executeQuery()) {
                if (result.next()) {
                    UUID tenantId = result.getObject("id", UUID.class);
                    try (PreparedStatement update = connection.prepareStatement("""
                            update platform.tenants
                            set name = ?, slug = ?, schema_name = ?, status = 'ACTIVE', updated_at = now()
                            where id = ?
                            """)) {
                        update.setString(1, DEFAULT_TENANT_NAME);
                        update.setString(2, DEFAULT_TENANT_SLUG);
                        update.setString(3, DEFAULT_TENANT_SCHEMA);
                        update.setObject(4, tenantId);
                        update.executeUpdate();
                    }
                    return new TenantSchema(tenantId, DEFAULT_TENANT_SCHEMA, "ACTIVE");
                }
            }
        }
        try (PreparedStatement insert = connection.prepareStatement("""
                insert into platform.tenants (
                    id, name, slug, schema_name, status, plan_code,
                    created_at, updated_at, max_connector_count,
                    max_service_account_count, max_daily_sbom_uploads,
                    max_export_rows, max_daily_exposure_refreshes
                ) values (?, ?, ?, ?, 'ACTIVE', 'ENTERPRISE', now(), now(), 10, 25, 100, 50000, 25)
                """)) {
            insert.setObject(1, DEFAULT_TENANT_ID);
            insert.setString(2, DEFAULT_TENANT_NAME);
            insert.setString(3, DEFAULT_TENANT_SLUG);
            insert.setString(4, DEFAULT_TENANT_SCHEMA);
            insert.executeUpdate();
        }
        return new TenantSchema(DEFAULT_TENANT_ID, DEFAULT_TENANT_SCHEMA, "ACTIVE");
    }

    private static BootstrapResult migrateExistingAndProvisioningTenants(
            Connection connection,
            Config config,
            TenantSchema defaultTenant,
            String templateChecksum,
            UUID runId
    ) throws Exception {
        List<Phase> phases = new ArrayList<>();
        List<TenantSchema> activeTenants = tenants(connection, "ACTIVE").stream()
                .filter(tenant -> !tenant.tenantId().equals(defaultTenant.tenantId()))
                .toList();
        if (!activeTenants.isEmpty()) {
            TenantSchema canary = activeTenants.get(0);
            migrateAndMark(connection, config, canary, templateChecksum, runId);
            phases.add(Phase.success("tenant_canary_migration", canary.schemaName()));
        }
        for (int offset = 1; offset < activeTenants.size(); offset += 10) {
            List<TenantSchema> batch = activeTenants.subList(offset, Math.min(offset + 10, activeTenants.size()));
            for (TenantSchema tenant : batch) {
                migrateAndMark(connection, config, tenant, templateChecksum, runId);
            }
            phases.add(Phase.success("tenant_batch_migration", "count=" + batch.size()));
        }

        List<TenantSchema> pending = tenants(connection, "PROVISIONING");
        for (TenantSchema tenant : pending) {
            try {
                provisionTenantSchema(connection, tenant.schemaName());
                migrateAndMark(connection, config, tenant, templateChecksum, runId);
                setTenantStatus(connection, tenant.tenantId(), "ACTIVE");
                phases.add(Phase.success("tenant_provisioning", tenant.schemaName()));
            } catch (Exception ex) {
                markFailure(connection, tenant, "PROVISIONING_FAILED", "PROVISIONING_FAILED", rootMessage(ex), runId);
                setTenantStatus(connection, tenant.tenantId(), "PROVISIONING_FAILED");
                phases.add(Phase.failed(
                        "tenant_provisioning_failed",
                        tenant.schemaName() + ": " + sanitize(rootMessage(ex))));
                return new BootstrapResult(false, phases);
            }
        }
        return new BootstrapResult(true, phases);
    }

    private static void migrateAndMark(
            Connection connection,
            Config config,
            TenantSchema tenant,
            String templateChecksum,
            UUID runId
    ) throws Exception {
        migrateTenant(config, tenant);
        String tenantChecksum = fingerprint(connection, tenant.schemaName());
        if (!templateChecksum.equals(tenantChecksum)) {
            throw new BootstrapFailure(
                    "tenant_schema_drift",
                    "Tenant schema does not match the migrated template: " + tenant.schemaName()
                            + " expected=" + templateChecksum + " actual=" + tenantChecksum);
        }
        markCurrent(connection, tenant, tenantChecksum, runId);
    }

    private static void migrateTenant(Config config, TenantSchema tenant) {
        Flyway.configure()
                .dataSource(config.dbUrl(), config.dbUsername(), config.dbPassword())
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

    private static void provisionTenantSchema(Connection connection, String schemaName) throws SQLException {
        if (DEFAULT_TENANT_SCHEMA.equals(schemaName) || "platform".equals(schemaName)) {
            throw new IllegalArgumentException("Refusing to provision protected schema: " + schemaName);
        }
        try (Statement statement = connection.createStatement()) {
            statement.execute("drop schema if exists " + quotedIdentifier(schemaName) + " cascade");
        }
        SingleConnectionDataSource dataSource = new SingleConnectionDataSource(connection, true);
        TenantSchemaService schemaService = new TenantSchemaService(
                new JdbcTemplate(dataSource), DEFAULT_TENANT_SCHEMA);
        schemaService.provisionOrReconcileSchemaFromTemplate(schemaName);
    }

    private static List<TenantSchema> tenants(Connection connection, String status) throws SQLException {
        List<TenantSchema> tenants = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement("""
                select id, schema_name, status
                from platform.tenants
                where deleted_at is null
                  and purged_at is null
                  and upper(status) = ?
                order by created_at, schema_name
                """)) {
            statement.setString(1, status);
            try (ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    tenants.add(new TenantSchema(
                            result.getObject("id", UUID.class),
                            result.getString("schema_name"),
                            result.getString("status")));
                }
            }
        }
        return tenants;
    }

    private static void markCurrent(Connection connection, TenantSchema tenant, String checksum, UUID runId) throws SQLException {
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
            statement.setObject(4, runId);
            statement.executeUpdate();
        }
    }

    private static void markFailure(
            Connection connection,
            TenantSchema tenant,
            String status,
            String code,
            String message,
            UUID runId
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                insert into platform.tenant_schema_versions (
                    tenant_id, schema_name, current_version, target_version, status,
                    structural_checksum, migration_started_at, migration_completed_at,
                    last_successful_version, failure_code, failure_message, updated_at, migration_run_id
                ) values (?, ?, 0, 44, ?, null, now(), now(), 0, ?, ?, now(), ?)
                on conflict (tenant_id) do update set
                    schema_name = excluded.schema_name,
                    status = excluded.status,
                    failure_code = excluded.failure_code,
                    failure_message = excluded.failure_message,
                    updated_at = now(),
                    migration_run_id = excluded.migration_run_id
                """)) {
            statement.setObject(1, tenant.tenantId());
            statement.setString(2, tenant.schemaName());
            statement.setString(3, status);
            statement.setString(4, code);
            statement.setString(5, sanitize(message));
            statement.setObject(6, runId);
            statement.executeUpdate();
        }
    }

    private static void setTenantStatus(Connection connection, UUID tenantId, String status) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                update platform.tenants
                set status = ?, updated_at = now()
                where id = ?
                """)) {
            statement.setString(1, status);
            statement.setObject(2, tenantId);
            statement.executeUpdate();
        }
    }

    private static void provisionRuntimeRole(Connection connection, String role, String password) throws SQLException {
        String quotedRole = quotedIdentifier(role);
        try (Statement statement = connection.createStatement()) {
            statement.execute("""
                    do $$
                    begin
                        if not exists (select 1 from pg_roles where rolname = %s) then
                            execute 'create role ' || %s || ' login noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls';
                        end if;
                    end
                    $$
                    """.formatted(quotedLiteral(role), quotedLiteral(quotedRole)));
            requireZero(connection, """
                    select count(*)
                    from pg_roles
                    where rolname = ?
                      and (rolsuper or rolcreatedb or rolcreaterole or rolreplication or rolbypassrls)
                    """, "runtime role has immutable unsafe attributes", role);
            statement.execute("alter role " + quotedRole
                    + " with login noinherit password "
                    + quotedLiteral(password));
            statement.execute("grant connect on database " + quotedIdentifier(connection.getCatalog()) + " to " + quotedRole);
            statement.execute("revoke create on database " + quotedIdentifier(connection.getCatalog()) + " from " + quotedRole);
            statement.execute("revoke create on schema public from " + quotedRole);
        }
        for (String schema : protectedSchemas(connection)) {
            try (Statement statement = connection.createStatement()) {
                String quotedSchema = quotedIdentifier(schema);
                statement.execute("grant usage on schema " + quotedSchema + " to " + quotedRole);
                statement.execute("grant select, insert, update, delete on all tables in schema " + quotedSchema + " to " + quotedRole);
                statement.execute("grant usage, select on all sequences in schema " + quotedSchema + " to " + quotedRole);
                statement.execute("revoke create on schema " + quotedSchema + " from " + quotedRole);
                statement.execute("alter default privileges for role " + quotedIdentifier(currentUser(connection))
                        + " in schema " + quotedSchema
                        + " grant select, insert, update, delete on tables to " + quotedRole);
                statement.execute("alter default privileges for role " + quotedIdentifier(currentUser(connection))
                        + " in schema " + quotedSchema
                        + " grant usage, select on sequences to " + quotedRole);
            }
        }
    }

    private static void verifyControlPlane(Connection connection, String runtimeRole) throws Exception {
        requireZero(connection, """
                select count(*)
                from public.flyway_schema_history
                where not success
                """, "failed platform flyway rows");
        requireMinimum(connection, """
                select coalesce(max(version::integer), 0)
                from public.flyway_schema_history
                where version ~ '^[0-9]+$'
                """, TARGET_VERSION, "platform version");
        requireZero(connection, """
                select count(*)
                from pg_roles
                where rolname = ?
                  and (rolsuper or rolinherit or rolcreaterole or rolcreatedb or rolreplication or rolbypassrls)
                """, "unsafe runtime role attributes", runtimeRole);
        requireZero(connection, """
                with recursive memberships(roleid) as (
                    select m.roleid
                    from pg_auth_members m
                    join pg_roles me on me.oid = m.member
                    where me.rolname = ?
                    union
                    select m.roleid
                    from pg_auth_members m
                    join memberships inherited on inherited.roleid = m.member
                )
                select count(*)
                from memberships m
                join pg_roles r on r.oid = m.roleid
                where r.rolsuper or r.rolbypassrls or r.rolcreaterole or r.rolcreatedb
                """, "runtime role can assume an unsafe role", runtimeRole);
        requireZero(connection, """
                select count(*)
                from pg_class c
                join pg_namespace n on n.oid = c.relnamespace
                join pg_roles r on r.oid = c.relowner
                where (n.nspname in ('platform', 'tenant_default') or n.nspname ~ '^tenant_')
                  and c.relkind in ('r', 'p')
                  and r.rolname = ?
                """, "runtime role owns protected tables", runtimeRole);
        requireZero(connection, """
                select count(*)
                from pg_namespace n
                where (n.nspname in ('platform', 'tenant_default') or n.nspname ~ '^tenant_')
                  and has_schema_privilege(?, n.oid, 'CREATE')
                """, "runtime role has protected-schema DDL privileges", runtimeRole);
        requireZero(connection, """
                select case when has_database_privilege(?, current_database(), 'CREATE') then 1 else 0 end
                """, "runtime role has database CREATE privilege", runtimeRole);
        requireZero(connection, """
                select count(*)
                from platform.tenants t
                join pg_namespace n on n.nspname = t.schema_name
                join pg_class c on c.relnamespace = n.oid and c.relkind in ('r', 'p')
                where t.deleted_at is null
                  and upper(t.status) = 'ACTIVE'
                  and c.relname not in ('tenant_schema_history', 'flyway_schema_history', 'demo_requests')
                  and (
                      not c.relrowsecurity
                      or not c.relforcerowsecurity
                      or not exists (
                          select 1 from pg_policy p
                          where p.polrelid = c.oid
                            and p.polname = 'tenant_isolation'
                            and pg_get_expr(p.polqual, p.polrelid) like '%app.current_tenant_id%'
                            and pg_get_expr(p.polwithcheck, p.polrelid) like '%app.current_tenant_id%'
                      )
                  )
                """, "active tenant tables have incomplete RLS coverage");
        requireZero(connection, """
                select count(*)
                from pg_class c
                join pg_namespace n on n.oid = c.relnamespace
                where (n.nspname in ('platform', 'tenant_default') or n.nspname ~ '^tenant_')
                  and c.relkind in ('r', 'p')
                  and not (
                      has_table_privilege(?, c.oid, 'SELECT')
                      and has_table_privilege(?, c.oid, 'INSERT')
                      and has_table_privilege(?, c.oid, 'UPDATE')
                      and has_table_privilege(?, c.oid, 'DELETE')
                  )
                """, "runtime role is missing required table DML privileges",
                runtimeRole, runtimeRole, runtimeRole, runtimeRole);
        requireZero(connection, """
                select count(*)
                from pg_class c
                join pg_namespace n on n.oid = c.relnamespace
                where (n.nspname in ('platform', 'tenant_default') or n.nspname ~ '^tenant_')
                  and c.relkind = 'S'
                  and not (
                      has_sequence_privilege(?, c.oid, 'USAGE')
                      and has_sequence_privilege(?, c.oid, 'SELECT')
                  )
                """, "runtime role is missing required sequence privileges", runtimeRole, runtimeRole);
        requireZero(connection, """
                select count(*)
                from platform.tenants t
                left join platform.tenant_schema_versions v on v.tenant_id = t.id
                where t.deleted_at is null
                  and upper(t.status) = 'ACTIVE'
                  and (v.tenant_id is null or v.status <> 'CURRENT'
                       or v.current_version < 44 or v.last_successful_version < 44)
                """, "active tenants missing current schema projection");
        verifyActiveTenantSchemaState(connection);
    }

    private static void verifyActiveTenantSchemaState(Connection connection) throws Exception {
        String templateChecksum = fingerprint(connection, DEFAULT_TENANT_SCHEMA);
        try (PreparedStatement statement = connection.prepareStatement("""
                select t.schema_name, v.structural_checksum
                from platform.tenants t
                join platform.tenant_schema_versions v on v.tenant_id = t.id
                where t.deleted_at is null
                  and upper(t.status) = 'ACTIVE'
                order by t.schema_name
                """);
             ResultSet result = statement.executeQuery()) {
            while (result.next()) {
                String schemaName = result.getString("schema_name");
                String recordedChecksum = result.getString("structural_checksum");
                requireMinimum(connection, """
                        select count(*)
                        from %s.tenant_schema_history
                        where version = '44' and success
                        """.formatted(quotedIdentifier(schemaName)), 1, schemaName + " tenant migration version");
                String actualChecksum = fingerprint(connection, schemaName);
                if (recordedChecksum == null
                        || !recordedChecksum.equals(actualChecksum)
                        || !templateChecksum.equals(actualChecksum)) {
                    throw new BootstrapFailure(
                            "verification_failed",
                            "active tenant schema checksum mismatch: " + schemaName);
                }
            }
        }
    }

    private static void verifyRuntimeConnection(Config config) throws SQLException {
        try (Connection connection = DriverManager.getConnection(
                config.dbUrl(), config.runtimeDbUsername(), config.runtimeDbPassword())) {
            if (!connection.getCatalog().equals(config.expectedDatabase())) {
                throw new BootstrapFailure("verification_failed", "runtime connection targets an unexpected database");
            }
            requireZero(connection, "select case when current_user = ? then 0 else 1 end",
                    "runtime role mismatch", config.runtimeDbUsername());
            requireZero(connection, """
                    select count(*)
                    from pg_roles
                    where rolname = current_user
                      and (rolsuper or rolinherit or rolcreaterole or rolcreatedb or rolreplication or rolbypassrls)
                    """, "runtime role is unsafe");
            verifyRuntimeDdlDenied(connection);
        }
    }

    private static void verifyRuntimeDdlDenied(Connection connection) throws SQLException {
        String tableName = "bootstrap_ddl_probe_" + UUID.randomUUID().toString().replace("-", "");
        try (Statement statement = connection.createStatement()) {
            statement.execute("create table platform." + quotedIdentifier(tableName) + " (id integer)");
            try (Connection cleanup = DriverManager.getConnection(
                    connection.getMetaData().getURL(),
                    required("DB_USERNAME"),
                    required("DB_PASSWORD"));
                 Statement cleanupStatement = cleanup.createStatement()) {
                cleanupStatement.execute("drop table if exists platform." + quotedIdentifier(tableName));
            }
            throw new BootstrapFailure("verification_failed", "runtime role can create protected tables");
        } catch (SQLException ex) {
            if (!"42501".equals(ex.getSQLState())) {
                throw ex;
            }
        }
    }

    private static void requireZero(Connection connection, String sql, String description, Object... params)
            throws SQLException {
        long value = queryLong(connection, sql, params);
        if (value != 0) {
            throw new BootstrapFailure("verification_failed", description + ": " + value);
        }
    }

    private static void requireMinimum(Connection connection, String sql, int minimum, String description)
            throws SQLException {
        long value = queryLong(connection, sql);
        if (value < minimum) {
            throw new BootstrapFailure("verification_failed", description + " is " + value);
        }
    }

    private static long queryLong(Connection connection, String sql, Object... params) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            for (int i = 0; i < params.length; i++) {
                statement.setObject(i + 1, params[i]);
            }
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    return 0;
                }
                return result.getLong(1);
            }
        }
    }

    private static int platformVersion(Connection connection) throws SQLException {
        return (int) queryLong(connection, """
                select coalesce(max(version::integer), 0)
                from public.flyway_schema_history
                where version ~ '^[0-9]+$'
                """);
    }

    private static List<String> protectedSchemas(Connection connection) throws SQLException {
        List<String> schemas = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement("""
                select nspname
                from pg_namespace
                where nspname in ('platform', 'tenant_default') or nspname ~ '^tenant_'
                order by nspname
                """);
             ResultSet result = statement.executeQuery()) {
            while (result.next()) {
                schemas.add(result.getString(1));
            }
        }
        return schemas;
    }

    private static String currentUser(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery("select current_user")) {
            result.next();
            return result.getString(1);
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
                    select concat_ws('|', 'index', tab.relname::text, idx.relname::text,
                           i.indisunique::text, i.indisprimary::text, i.indkey::text,
                           i.indclass::text, i.indcollation::text, i.indoption::text,
                           regexp_replace(
                               regexp_replace(coalesce(pg_get_expr(i.indexprs, i.indrelid), ''),
                                   '::(character varying|text)(\\[\\])?', '', 'g'),
                               '[()[:space:]]', '', 'g'),
                           regexp_replace(
                               regexp_replace(coalesce(pg_get_expr(i.indpred, i.indrelid), ''),
                                   '::(character varying|text)(\\[\\])?', '', 'g'),
                               '[()[:space:]]', '', 'g'))::text
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
        String originalSearchPath;
        try (Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery("SHOW search_path")) {
            result.next();
            originalSearchPath = result.getString(1);
        }
        try {
            try (PreparedStatement setSearchPath = connection.prepareStatement(
                    "select set_config('search_path', 'pg_catalog', false)")) {
                setSearchPath.execute();
            }
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
        } finally {
            try (PreparedStatement restoreSearchPath = connection.prepareStatement(
                    "select set_config('search_path', ?, false)")) {
                restoreSearchPath.setString(1, originalSearchPath);
                restoreSearchPath.execute();
            }
        }
        String normalized = String.join("\n", definitions).replace(schemaName, "<tenant_schema>");
        normalized = UUID_VALUE.matcher(normalized).replaceAll("<tenant_id>");
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(normalized.getBytes(StandardCharsets.UTF_8)));
    }

    private static void acquireLock(Connection connection) throws SQLException {
        Instant deadline = Instant.now().plusSeconds(30);
        while (Instant.now().isBefore(deadline)) {
            try (PreparedStatement statement = connection.prepareStatement("select pg_try_advisory_lock(hashtext(?))")) {
                statement.setString(1, LOCK_NAME);
                try (ResultSet result = statement.executeQuery()) {
                    if (result.next() && result.getBoolean(1)) {
                        return;
                    }
                }
            }
            try {
                Thread.sleep(250);
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                throw new BootstrapFailure("lock_interrupted", "Interrupted while waiting for bootstrap lock");
            }
        }
        throw new BootstrapFailure("lock_timeout", "Timed out waiting for bootstrap lock");
    }

    private static void releaseLock(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("select pg_advisory_unlock(hashtext(?))")) {
            statement.setString(1, LOCK_NAME);
            statement.execute();
        }
    }

    private static String quotedIdentifier(String value) {
        if (value == null || value.indexOf('\u0000') >= 0) {
            throw new IllegalArgumentException("Unsafe SQL identifier");
        }
        return "\"" + value.replace("\"", "\"\"") + "\"";
    }

    private static String quotedLiteral(String value) {
        if (value == null) {
            return "null";
        }
        return "'" + value.replace("'", "''") + "'";
    }

    private static String sanitize(String message) {
        if (message == null) {
            return null;
        }
        String sanitized = message
                .replaceAll("(?i)(password|secret|token|key)=\\S+", "$1=[REDACTED]")
                .replaceAll("jdbc:postgresql://[^\\s,}]+", "jdbc:postgresql://[REDACTED]");
        return sanitized.substring(0, Math.min(1000, sanitized.length()));
    }

    private static String rootMessage(Throwable throwable) {
        Throwable current = throwable;
        while (current.getCause() != null && current.getCause() != current) {
            current = current.getCause();
        }
        return current.getMessage() == null ? current.getClass().getSimpleName() : current.getMessage();
    }

    private static String report(
            UUID runId,
            Instant startedAt,
            Instant completedAt,
            boolean success,
            String failureCode,
            String failureMessage,
            List<Phase> phases
    ) {
        StringBuilder json = new StringBuilder();
        json.append('{')
                .append("\"runId\":\"").append(runId).append("\",")
                .append("\"startedAt\":\"").append(startedAt).append("\",")
                .append("\"completedAt\":\"").append(completedAt).append("\",")
                .append("\"success\":").append(success).append(',')
                .append("\"failureCode\":").append(jsonString(failureCode)).append(',')
                .append("\"failureMessage\":").append(jsonString(failureMessage)).append(',')
                .append("\"phases\":[");
        for (int i = 0; i < phases.size(); i++) {
            Phase phase = phases.get(i);
            if (i > 0) {
                json.append(',');
            }
            json.append('{')
                    .append("\"name\":\"").append(escape(phase.name())).append("\",")
                    .append("\"success\":").append(phase.success()).append(',')
                    .append("\"message\":").append(jsonString(phase.message()))
                    .append('}');
        }
        json.append("]}");
        return "production_bootstrap_report=" + json;
    }

    private static String jsonString(String value) {
        return value == null ? "null" : "\"" + escape(value) + "\"";
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private record Config(
            String dbUrl,
            String dbUsername,
            String dbPassword,
            String runtimeDbUsername,
            String runtimeDbPassword,
            String expectedDatabase,
            boolean reportOnly
    ) {
        static Config fromEnvironment() {
            String dbUrl = required("DB_URL");
            return new Config(
                    dbUrl,
                    required("DB_USERNAME"),
                    required("DB_PASSWORD"),
                    env("RUNTIME_DB_USERNAME", "scout_runtime"),
                    required("RUNTIME_DB_PASSWORD"),
                    env("EXPECTED_DB_NAME", databaseName(dbUrl)),
                    Boolean.parseBoolean(env(
                            "BOOTSTRAP_REPORT_ONLY",
                            env("APP_SCHEMA_MIGRATION_REPORT_ONLY", "false"))));
        }
    }

    private static String databaseName(String jdbcUrl) {
        int queryIndex = jdbcUrl.indexOf('?');
        String withoutQuery = queryIndex >= 0 ? jdbcUrl.substring(0, queryIndex) : jdbcUrl;
        int slashIndex = withoutQuery.lastIndexOf('/');
        if (slashIndex < 0 || slashIndex == withoutQuery.length() - 1) {
            throw new IllegalArgumentException("DB_URL must include a database name");
        }
        return withoutQuery.substring(slashIndex + 1);
    }

    private record TenantSchema(UUID tenantId, String schemaName, String status) {
    }

    private record BootstrapResult(boolean success, List<Phase> phases) {
    }

    private record Phase(String name, boolean success, String message) {
        static Phase success(String name, String message) {
            return new Phase(name, true, sanitize(message));
        }

        static Phase failed(String name, String message) {
            return new Phase(name, false, sanitize(message));
        }
    }

    private static class BootstrapFailure extends RuntimeException {
        private final String code;

        BootstrapFailure(String code, String message) {
            super(message);
            this.code = code;
        }

        String code() {
            return code;
        }
    }

    private static String required(String name) {
        if (System.getProperties().containsKey(name)) {
            return System.getProperty(name, "");
        }
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " is required");
        }
        return value;
    }

    private static String env(String name, String defaultValue) {
        String value = System.getProperty(name);
        if (value == null || value.isBlank()) {
            value = System.getenv(name);
        }
        return value == null || value.isBlank() ? defaultValue : value;
    }
}
