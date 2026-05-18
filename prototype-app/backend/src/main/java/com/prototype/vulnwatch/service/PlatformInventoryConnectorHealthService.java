package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.dto.InventoryConnectorHealthResponse;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;

@Service
public class PlatformInventoryConnectorHealthService {

    private final JdbcTemplate platformJdbcTemplate;

    public PlatformInventoryConnectorHealthService(@Qualifier("platformJdbcTemplate") JdbcTemplate platformJdbcTemplate) {
        this.platformJdbcTemplate = platformJdbcTemplate;
    }

    public List<InventoryConnectorHealthResponse> listInventoryConnectorHealth() {
        List<InventoryConnectorHealthResponse> responses = new ArrayList<>();
        responses.addAll(platformJdbcTemplate.query("""
                select c.tenant_id,
                       t.name as tenant_name,
                       'servicenow' as connector_key,
                       c.enabled,
                       c.auto_sync_enabled,
                       c.last_test_status,
                       c.last_test_message,
                       c.last_tested_at,
                       c.last_sync_at
                from servicenow_cmdb_configs c
                join tenants t on t.id = c.tenant_id
                """, rowMapper()));
        responses.addAll(platformJdbcTemplate.query("""
                select c.tenant_id,
                       t.name as tenant_name,
                       'sccm' as connector_key,
                       c.enabled,
                       c.auto_sync_enabled,
                       c.last_test_status,
                       c.last_test_message,
                       c.last_tested_at,
                       c.last_sync_at
                from sccm_cmdb_configs c
                join tenants t on t.id = c.tenant_id
                """, rowMapper()));
        responses.addAll(platformJdbcTemplate.query("""
                select c.tenant_id,
                       t.name as tenant_name,
                       'aws' as connector_key,
                       c.enabled,
                       c.auto_sync_enabled,
                       c.last_test_status,
                       c.last_test_message,
                       c.last_tested_at,
                       c.last_sync_at
                from aws_discovery_configs c
                join tenants t on t.id = c.tenant_id
                """, rowMapper()));
        responses.sort(Comparator
                .comparing(InventoryConnectorHealthResponse::tenantName, Comparator.nullsLast(String::compareToIgnoreCase))
                .thenComparing(InventoryConnectorHealthResponse::connectorKey, Comparator.nullsLast(String::compareToIgnoreCase)));
        return responses;
    }

    private RowMapper<InventoryConnectorHealthResponse> rowMapper() {
        return (rs, rowNum) -> new InventoryConnectorHealthResponse(
                UUID.fromString(rs.getString("tenant_id")),
                rs.getString("tenant_name"),
                rs.getString("connector_key"),
                rs.getBoolean("enabled"),
                rs.getBoolean("auto_sync_enabled"),
                rs.getString("last_test_status"),
                sanitize(rs.getString("last_test_message")),
                timestamp(rs, "last_tested_at"),
                timestamp(rs, "last_sync_at"),
                deriveHealthState(
                        rs.getBoolean("enabled"),
                        rs.getString("last_test_status"),
                        timestamp(rs, "last_sync_at")
                )
        );
    }

    private Instant timestamp(ResultSet rs, String column) throws SQLException {
        return rs.getTimestamp(column) == null ? null : rs.getTimestamp(column).toInstant();
    }

    private String deriveHealthState(boolean enabled, String lastTestStatus, Instant lastSyncAt) {
        if (!enabled) {
            return "DISABLED";
        }
        if (lastTestStatus != null && lastTestStatus.equalsIgnoreCase("FAILED")) {
            return "ERROR";
        }
        if (lastSyncAt == null) {
            return "PENDING";
        }
        return "HEALTHY";
    }

    private String sanitize(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String sanitized = value.trim();
        return sanitized.length() > 240 ? sanitized.substring(0, 240) + "..." : sanitized;
    }
}
