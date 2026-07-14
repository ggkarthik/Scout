package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.dto.TenantSchemaStatusResponse;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class TenantSchemaStatusService {

    public static final int TARGET_VERSION = 42;

    private final JdbcTemplate jdbc;

    public TenantSchemaStatusService(@Qualifier("platformJdbcTemplate") JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public TenantSchemaStatusResponse list(int requestedPage, int requestedSize) {
        int page = Math.max(0, requestedPage);
        int size = Math.min(200, Math.max(1, requestedSize));
        Long total = jdbc.queryForObject("select count(*) from platform.tenant_schema_versions", Long.class);
        List<TenantSchemaStatusResponse.Item> items = jdbc.query("""
                select tenant_id, schema_name, current_version, target_version, status,
                       structural_checksum, last_successful_version, failure_code, failure_message,
                       migration_started_at, migration_completed_at, updated_at, migration_run_id
                from platform.tenant_schema_versions
                order by schema_name
                limit ? offset ?
                """, (rs, rowNum) -> new TenantSchemaStatusResponse.Item(
                rs.getObject("tenant_id", UUID.class),
                rs.getString("schema_name"),
                rs.getInt("current_version"),
                rs.getInt("target_version"),
                rs.getString("status"),
                rs.getString("structural_checksum"),
                rs.getInt("last_successful_version"),
                rs.getString("failure_code"),
                rs.getString("failure_message"),
                instant(rs.getTimestamp("migration_started_at")),
                instant(rs.getTimestamp("migration_completed_at")),
                instant(rs.getTimestamp("updated_at")),
                rs.getObject("migration_run_id", UUID.class)
        ), size, page * size);
        return new TenantSchemaStatusResponse(items, page, size, total == null ? 0 : total);
    }

    public long readinessFailures(int minimumVersion) {
        Long count = jdbc.queryForObject("""
                select count(*)
                from platform.tenants t
                left join platform.tenant_schema_versions v on v.tenant_id = t.id
                where t.status = 'ACTIVE'
                  and (v.tenant_id is null
                       or v.status in ('FAILED', 'DRIFTED', 'PROVISIONING_FAILED')
                       or v.status <> 'CURRENT'
                       or v.current_version < ?)
                """, Long.class, minimumVersion);
        return count == null ? 0 : count;
    }

    public void markMigrating(UUID tenantId, String schemaName, UUID runId) {
        upsert(tenantId, schemaName, 0, "MIGRATING", null, null, null, runId, true);
    }

    public void markCurrent(UUID tenantId, String schemaName, int version, String checksum, UUID runId) {
        upsert(tenantId, schemaName, version, "CURRENT", checksum, null, null, runId, false);
    }

    public void markFailure(UUID tenantId, String schemaName, String status, String code, String message, UUID runId) {
        upsert(tenantId, schemaName, 0, status, null, code, sanitize(message), runId, false);
    }

    private void upsert(
            UUID tenantId,
            String schemaName,
            int version,
            String status,
            String checksum,
            String failureCode,
            String failureMessage,
            UUID runId,
            boolean starting
    ) {
        jdbc.update("""
                insert into platform.tenant_schema_versions (
                    tenant_id, schema_name, current_version, target_version, status,
                    structural_checksum, migration_started_at, migration_completed_at,
                    last_successful_version, failure_code, failure_message, updated_at, migration_run_id
                ) values (?, ?, ?, ?, ?, ?, case when ? then now() else null end,
                          case when ? then null else now() end, ?, ?, ?, now(), ?)
                on conflict (tenant_id) do update set
                    schema_name = excluded.schema_name,
                    current_version = case when excluded.current_version = 0
                        then platform.tenant_schema_versions.current_version else excluded.current_version end,
                    target_version = excluded.target_version,
                    status = excluded.status,
                    structural_checksum = coalesce(excluded.structural_checksum, platform.tenant_schema_versions.structural_checksum),
                    migration_started_at = case when ? then now() else platform.tenant_schema_versions.migration_started_at end,
                    migration_completed_at = case when ? then null else now() end,
                    last_successful_version = greatest(platform.tenant_schema_versions.last_successful_version, excluded.last_successful_version),
                    failure_code = excluded.failure_code,
                    failure_message = excluded.failure_message,
                    updated_at = now(),
                    migration_run_id = excluded.migration_run_id
                """, tenantId, schemaName, version, TARGET_VERSION, status, checksum,
                starting, starting, version, failureCode, failureMessage, runId, starting, starting);
    }

    private String sanitize(String message) {
        if (message == null) {
            return null;
        }
        String sanitized = message.replaceAll("(?i)(password|secret|token|key)=[^\\s,;]+", "$1=[REDACTED]");
        return sanitized.substring(0, Math.min(1000, sanitized.length()));
    }

    private static Instant instant(Timestamp value) {
        return value == null ? null : value.toInstant();
    }
}
