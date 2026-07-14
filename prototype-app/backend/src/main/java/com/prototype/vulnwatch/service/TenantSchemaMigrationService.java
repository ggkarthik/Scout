package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.zaxxer.hikari.HikariDataSource;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class TenantSchemaMigrationService {

    private static final String LOCK_NAME = "scout-tenant-schema-migrator";
    private static final Duration LOCK_TIMEOUT = Duration.ofSeconds(30);
    private static final Pattern UUID_VALUE = Pattern.compile(
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}");

    private final HikariDataSource dataSource;
    private final JdbcTemplate jdbc;
    private final TenantRepository tenantRepository;
    private final TenantSchemaService schemaService;
    private final TenantSchemaStatusService statusService;

    public TenantSchemaMigrationService(
            @Qualifier("hikariDataSource") HikariDataSource dataSource,
            @Qualifier("platformJdbcTemplate") JdbcTemplate jdbc,
            TenantRepository tenantRepository,
            TenantSchemaService schemaService,
            TenantSchemaStatusService statusService
    ) {
        this.dataSource = dataSource;
        this.jdbc = jdbc;
        this.tenantRepository = tenantRepository;
        this.schemaService = schemaService;
        this.statusService = statusService;
    }

    public MigrationReport migrateAll(boolean reportOnly) {
        UUID runId = UUID.randomUUID();
        Instant startedAt = Instant.now();
        List<SchemaResult> results = new ArrayList<>();
        try (Connection lockConnection = dataSource.getConnection()) {
            acquireLock(lockConnection);
            try {
            List<Tenant> tenants = tenantRepository.findAllByOrderByCreatedAtAsc();
            Tenant templateTenant = tenants.stream()
                    .filter(t -> schemaService.defaultSchemaName().equals(t.getSchemaName()))
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException("Default tenant registration is required before migration"));

            String templateFingerprint = structuralFingerprint(schemaService.defaultSchemaName());
            for (Tenant tenant : tenants) {
                if (tenant.getId().equals(templateTenant.getId())) {
                    continue;
                }
                results.add(reconcileAndBaseline(tenant, templateFingerprint, reportOnly, runId));
                if (!reportOnly && results.get(results.size() - 1).failed()) {
                    return report(runId, startedAt, results, false, "reconciliation_failed");
                }
            }
            if (reportOnly) {
                results.add(new SchemaResult(templateTenant.getId(), templateTenant.getSchemaName(),
                        "REPORT_ONLY", 41, templateFingerprint, null));
                boolean clean = results.stream().noneMatch(SchemaResult::failed);
                return report(runId, startedAt, results, clean, clean ? null : "structural_drift");
            }

            SchemaResult templateResult = migrateOne(templateTenant, runId);
            results.add(templateResult);
            if (templateResult.failed()) {
                return report(runId, startedAt, results, false, "template_failed");
            }

            List<Tenant> remaining = tenants.stream()
                    .filter(t -> !t.getId().equals(templateTenant.getId()))
                    .toList();
            if (!remaining.isEmpty()) {
                SchemaResult canary = migrateOne(remaining.get(0), runId);
                results.add(canary);
                if (canary.failed()) {
                    return report(runId, startedAt, results, false, "canary_failed");
                }
            }
            for (int offset = 1; offset < remaining.size(); offset += 10) {
                List<Tenant> batch = remaining.subList(offset, Math.min(offset + 10, remaining.size()));
                for (Tenant tenant : batch) {
                    SchemaResult result = migrateOne(tenant, runId);
                    results.add(result);
                    if (result.failed()) {
                        return report(runId, startedAt, results, false, "batch_failed");
                    }
                }
            }
            return report(runId, startedAt, results, true, null);
            } finally {
                releaseLock(lockConnection);
            }
        } catch (SQLException ex) {
            throw new IllegalStateException("Unable to hold the tenant migrator advisory lock", ex);
        }
    }

    public void provisionNewTenant(Tenant tenant) {
        UUID runId = UUID.randomUUID();
        try {
            schemaService.provisionSchemaFromTemplate(tenant.getSchemaName());
            SchemaResult result = migrateOne(tenant, runId);
            if (result.failed()) {
                throw new IllegalStateException(result.failureMessage());
            }
        } catch (RuntimeException ex) {
            statusService.markFailure(tenant.getId(), tenant.getSchemaName(), "PROVISIONING_FAILED",
                    "PROVISIONING_FAILED", ex.getMessage(), runId);
            throw ex;
        }
    }

    private SchemaResult reconcileAndBaseline(
            Tenant tenant,
            String templateFingerprint,
            boolean reportOnly,
            UUID runId
    ) {
        String schema = schemaService.schemaNameForTenant(tenant);
        try {
            schemaService.assertSchemaReady(schema);
            String before = structuralFingerprint(schema);
            if (reportOnly) {
                String status = before.equals(templateFingerprint) ? "BASELINEABLE" : "DRIFTED";
                return new SchemaResult(tenant.getId(), schema, status, 41, before,
                        before.equals(templateFingerprint) ? null : "Structural drift requires reconciliation");
            }
            schemaService.reconcileSafeDifferences(schema);
            String after = structuralFingerprint(schema);
            if (!after.equals(templateFingerprint)) {
                statusService.markFailure(tenant.getId(), schema, "DRIFTED", "STRUCTURAL_DRIFT",
                        "Schema does not match the normalized version-41 template", runId);
                return new SchemaResult(tenant.getId(), schema, "DRIFTED", 0, after,
                        "Schema does not match the normalized version-41 template");
            }
            return new SchemaResult(tenant.getId(), schema, "BASELINEABLE", 41, after, null);
        } catch (RuntimeException ex) {
            if (!reportOnly) {
                statusService.markFailure(tenant.getId(), schema, "DRIFTED", "RECONCILIATION_FAILED",
                        ex.getMessage(), runId);
            }
            return new SchemaResult(tenant.getId(), schema, "DRIFTED", 0, null, ex.getMessage());
        }
    }

    private SchemaResult migrateOne(Tenant tenant, UUID runId) {
        String schema = schemaService.schemaNameForTenant(tenant);
        statusService.markMigrating(tenant.getId(), schema, runId);
        try {
            Map<String, String> placeholders = new LinkedHashMap<>();
            placeholders.put("tenantId", tenant.getId().toString());
            placeholders.put("tenantSchema", schema);
            Flyway flyway = Flyway.configure()
                    .dataSource(dataSource)
                    .schemas(schema)
                    .defaultSchema(schema)
                    .table("tenant_schema_history")
                    .locations("classpath:db/migration/tenant")
                    .baselineOnMigrate(true)
                    .baselineVersion(MigrationVersion.fromVersion("41"))
                    .baselineDescription("legacy tenant schema baseline")
                    .placeholders(placeholders)
                    .validateOnMigrate(true)
                    .outOfOrder(false)
                    .initSql("SET statement_timeout = '5min'")
                    .load();
            flyway.migrate();
            int version = Integer.parseInt(flyway.info().current().getVersion().getVersion());
            String checksum = structuralFingerprint(schema);
            statusService.markCurrent(tenant.getId(), schema, version, checksum, runId);
            return new SchemaResult(tenant.getId(), schema, "CURRENT", version, checksum, null);
        } catch (RuntimeException ex) {
            statusService.markFailure(tenant.getId(), schema, "FAILED", "MIGRATION_FAILED", ex.getMessage(), runId);
            return new SchemaResult(tenant.getId(), schema, "FAILED", 0, null, ex.getMessage());
        }
    }

    public String structuralFingerprint(String schemaName) {
        List<String> objects = jdbc.queryForList("""
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
                """, String.class, schemaName, schemaName, schemaName, schemaName, schemaName);
        String normalized = String.join("\n", objects)
                .replace(schemaName, "<tenant_schema>");
        normalized = UUID_VALUE.matcher(normalized).replaceAll("<tenant_id>");
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(normalized.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to compute tenant schema checksum", ex);
        }
    }

    private void acquireLock(Connection connection) throws SQLException {
        Instant deadline = Instant.now().plus(LOCK_TIMEOUT);
        while (Instant.now().isBefore(deadline)) {
            try (PreparedStatement statement = connection.prepareStatement(
                    "select pg_try_advisory_lock(hashtext(?))")) {
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
                throw new IllegalStateException("Interrupted while waiting for tenant migrator lock", ex);
            }
        }
        throw new IllegalStateException("Timed out after 30 seconds waiting for tenant migrator lock");
    }

    private void releaseLock(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "select pg_advisory_unlock(hashtext(?))")) {
            statement.setString(1, LOCK_NAME);
            statement.execute();
        }
    }

    private MigrationReport report(UUID runId, Instant startedAt, List<SchemaResult> results,
                                   boolean success, String failureCode) {
        return new MigrationReport(runId, startedAt, Instant.now(), success, failureCode, List.copyOf(results));
    }

    public record MigrationReport(UUID runId, Instant startedAt, Instant completedAt, boolean success,
                                  String failureCode, List<SchemaResult> schemas) {
    }

    public record SchemaResult(UUID tenantId, String schemaName, String status, int version,
                               String checksum, String failureMessage) {
        public boolean failed() {
            return "FAILED".equals(status) || "DRIFTED".equals(status);
        }
    }
}
