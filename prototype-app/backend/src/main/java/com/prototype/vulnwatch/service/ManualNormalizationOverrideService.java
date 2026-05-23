package com.prototype.vulnwatch.service;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ManualNormalizationOverrideService {

    private final NamedParameterJdbcTemplate jdbcTemplate;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;

    public ManualNormalizationOverrideService(
            NamedParameterJdbcTemplate jdbcTemplate,
            TenantSchemaExecutionService tenantSchemaExecutionService
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
    }

    @Transactional
    public void applyOverride(UUID tenantId, UUID componentId, UUID softwareIdentityId, String reason, String actor) {
        tenantSchemaExecutionService.run(tenantId, () -> {
            String sql = """
                    UPDATE inventory_components
                    SET manual_identity_id            = :softwareIdentityId,
                        manual_identity_reason         = :reason,
                        manual_identity_confirmed_by   = :actor,
                        manual_identity_confirmed_at   = now()
                    WHERE id = :componentId
                    """;
            MapSqlParameterSource params = new MapSqlParameterSource()
                    .addValue("softwareIdentityId", softwareIdentityId)
                    .addValue("reason", reason)
                    .addValue("actor", actor)
                    .addValue("componentId", componentId)
                    .addValue("tenantId", tenantId);
            jdbcTemplate.update(sql, params);
            return null;
        });
    }

    @Transactional
    public void revokeOverride(UUID tenantId, UUID componentId) {
        tenantSchemaExecutionService.run(tenantId, () -> {
            String sql = """
                    UPDATE inventory_components
                    SET manual_identity_id            = NULL,
                        manual_identity_reason         = NULL,
                        manual_identity_confirmed_by   = NULL,
                        manual_identity_confirmed_at   = NULL
                    WHERE id = :componentId
                    """;
            MapSqlParameterSource params = new MapSqlParameterSource()
                    .addValue("componentId", componentId)
                    .addValue("tenantId", tenantId);
            jdbcTemplate.update(sql, params);
            return null;
        });
    }

    public List<SoftwareIdentityMatch> searchSoftwareIdentities(UUID tenantId, String query, int limit) {
        return tenantSchemaExecutionService.run(tenantId, () -> {
            String sql = """
                    SELECT software_identity_id, display_name, canonical_key
                    FROM software_identity_summary
                    WHERE display_name ILIKE :pattern
                       OR canonical_key ILIKE :pattern
                    ORDER BY component_count DESC, display_name ASC
                    LIMIT :limit
                    """;
            String pattern = "%" + query.replace("%", "\\%").replace("_", "\\_") + "%";
            MapSqlParameterSource params = new MapSqlParameterSource()
                    .addValue("tenantId", tenantId)
                    .addValue("pattern", pattern)
                    .addValue("limit", limit);
            List<SoftwareIdentityMatch> results = new ArrayList<>();
            for (var row : jdbcTemplate.queryForList(sql, params)) {
                results.add(new SoftwareIdentityMatch(
                        (UUID) row.get("software_identity_id"),
                        (String) row.get("display_name"),
                        (String) row.get("canonical_key")
                ));
            }
            return results;
        });
    }

    @Transactional
    public void applyOverrideToSoftwareInstance(UUID tenantId, UUID softwareInstanceId, UUID softwareIdentityId, String reason, String actor) {
        // Sets software_identity_id directly — manual_identity_* columns were never migrated
        // onto software_instances. Per-instance overrides on host software are superseded by
        // NormalizationClusterOverrideService; this fallback handles any legacy path.
        tenantSchemaExecutionService.run(tenantId, () -> {
            String sql = """
                    UPDATE software_instances
                    SET software_identity_id = :softwareIdentityId
                    WHERE id = :softwareInstanceId
                    """;
            MapSqlParameterSource params = new MapSqlParameterSource()
                    .addValue("softwareIdentityId", softwareIdentityId)
                    .addValue("softwareInstanceId", softwareInstanceId)
                    .addValue("tenantId", tenantId);
            jdbcTemplate.update(sql, params);
            return null;
        });
    }

    @Transactional
    public void revokeOverrideFromSoftwareInstance(UUID tenantId, UUID softwareInstanceId) {
        tenantSchemaExecutionService.run(tenantId, () -> {
            String sql = """
                    UPDATE software_instances
                    SET software_identity_id = NULL
                    WHERE id = :softwareInstanceId
                    """;
            MapSqlParameterSource params = new MapSqlParameterSource()
                    .addValue("softwareInstanceId", softwareInstanceId)
                    .addValue("tenantId", tenantId);
            jdbcTemplate.update(sql, params);
            return null;
        });
    }

    public record SoftwareIdentityMatch(UUID id, String displayName, String canonicalKey) {}
}
