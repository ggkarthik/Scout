package com.prototype.vulnwatch.service;

import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Cluster-level normalization override service.
 *
 * A single override action on a cluster key (e.g. discovery_model.primary_key or
 * ecosystem:package_name) propagates to all matching software_instances /
 * inventory_components in one bulk UPDATE, resolving N quality issues at once.
 */
@Service
public class NormalizationClusterOverrideService {

    private final NamedParameterJdbcTemplate jdbcTemplate;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;

    public NormalizationClusterOverrideService(
            NamedParameterJdbcTemplate jdbcTemplate,
            TenantSchemaExecutionService tenantSchemaExecutionService
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
    }

    /**
     * Count affected records before applying the override (impact preview).
     */
    public ClusterImpactResult getClusterImpact(UUID tenantId, String sourceType, String sourceKey) {
        return tenantSchemaExecutionService.run(tenantId, () -> {
            if ("DISCOVERY_MODEL".equals(sourceType) || "CLUSTER_DISCOVERY_MODEL".equals(sourceType)) {
                String sql = """
                        SELECT COUNT(DISTINCT ci.asset_id) AS asset_count,
                               COUNT(si.id)               AS instance_count
                        FROM software_instances si
                        JOIN cis ci ON ci.id = si.ci_id
                        JOIN discovery_models dm ON dm.id = si.discovery_model_id
                        WHERE dm.primary_key = :sourceKey
                          AND si.active_install = true
                        """;
                return jdbcTemplate.query(sql,
                        new MapSqlParameterSource()
                                .addValue("tenantId", tenantId)
                                .addValue("sourceKey", sourceKey),
                        rs -> rs.next()
                                ? new ClusterImpactResult(rs.getLong("asset_count"), rs.getLong("instance_count"))
                                : new ClusterImpactResult(0L, 0L));
            } else {
                String[] parts = parsePackageKey(sourceKey);
                String ecosystem = parts[0];
                String packageName = parts[1];
                String sql = """
                        SELECT COUNT(DISTINCT ic.asset_id) AS asset_count,
                               COUNT(ic.id)               AS component_count
                        FROM inventory_components ic
                        WHERE ic.ecosystem  = :ecosystem
                          AND ic.package_name = :packageName
                          AND ic.component_status = 'ACTIVE'
                        """;
                return jdbcTemplate.query(sql,
                        new MapSqlParameterSource()
                                .addValue("tenantId", tenantId)
                                .addValue("ecosystem", ecosystem)
                                .addValue("packageName", packageName),
                        rs -> rs.next()
                                ? new ClusterImpactResult(rs.getLong("asset_count"), rs.getLong("component_count"))
                                : new ClusterImpactResult(0L, 0L));
            }
        });
    }

    /**
     * Write the cluster link and cascade-update all matching records immediately.
     */
    @Transactional
    public void applyClusterOverride(
            UUID tenantId,
            String sourceType,
            String sourceKey,
            UUID targetIdentityId,
            boolean applyToFuture,
            String reason,
            String actor
    ) {
        tenantSchemaExecutionService.run(tenantId, () -> {
            String normalizedType = normalizeType(sourceType);
            String upsertSql = """
                    INSERT INTO software_identity_cluster_link
                        (tenant_id, source_type, source_key, target_identity_id,
                         apply_to_future, reason, confirmed_by, confirmed_at,
                         revoked_at, revoked_by)
                    VALUES
                        (:tenantId, :sourceType, :sourceKey, :targetIdentityId,
                         :applyToFuture, :reason, :actor, now(),
                         NULL, NULL)
                    ON CONFLICT (tenant_id, source_type, source_key)
                        WHERE revoked_at IS NULL
                    DO UPDATE SET
                        target_identity_id = EXCLUDED.target_identity_id,
                        apply_to_future    = EXCLUDED.apply_to_future,
                        reason             = EXCLUDED.reason,
                        confirmed_by       = EXCLUDED.confirmed_by,
                        confirmed_at       = EXCLUDED.confirmed_at,
                        revoked_at         = NULL,
                        revoked_by         = NULL
                    """;
            jdbcTemplate.update("""
                    DELETE FROM software_identity_cluster_link
                    WHERE source_type = :sourceType
                      AND source_key  = :sourceKey
                      AND revoked_at IS NOT NULL
                    """,
                    new MapSqlParameterSource()
                            .addValue("tenantId", tenantId)
                            .addValue("sourceType", normalizedType)
                            .addValue("sourceKey", sourceKey));

            jdbcTemplate.update(upsertSql,
                    new MapSqlParameterSource()
                            .addValue("tenantId", tenantId)
                            .addValue("sourceType", normalizedType)
                            .addValue("sourceKey", sourceKey)
                            .addValue("targetIdentityId", targetIdentityId)
                            .addValue("applyToFuture", applyToFuture)
                            .addValue("reason", reason)
                            .addValue("actor", actor));

            if ("DISCOVERY_MODEL".equals(normalizedType)) {
                jdbcTemplate.update("""
                        UPDATE software_instances si
                        SET software_identity_id = :targetIdentityId
                        FROM cis ci, discovery_models dm
                        WHERE si.ci_id = ci.id
                          AND si.discovery_model_id = dm.id
                          AND dm.primary_key = :sourceKey
                          AND si.active_install = true
                        """,
                        new MapSqlParameterSource()
                                .addValue("tenantId", tenantId)
                                .addValue("targetIdentityId", targetIdentityId)
                                .addValue("sourceKey", sourceKey));
            } else {
                String[] parts = parsePackageKey(sourceKey);
                jdbcTemplate.update("""
                        UPDATE inventory_components
                        SET software_identity_id = :targetIdentityId
                        WHERE ecosystem   = :ecosystem
                          AND package_name = :packageName
                          AND component_status = 'ACTIVE'
                        """,
                        new MapSqlParameterSource()
                                .addValue("tenantId", tenantId)
                                .addValue("targetIdentityId", targetIdentityId)
                                .addValue("ecosystem", parts[0])
                                .addValue("packageName", parts[1]));
            }
            return null;
        });
    }

    /**
     * Soft-delete the cluster link and clear software_identity_id on previously-linked records.
     */
    @Transactional
    public void revokeClusterOverride(UUID tenantId, String sourceType, String sourceKey, String actor) {
        tenantSchemaExecutionService.run(tenantId, () -> {
            String normalizedType = normalizeType(sourceType);
            int updated = jdbcTemplate.update("""
                    UPDATE software_identity_cluster_link
                    SET revoked_at = now(),
                        revoked_by = :actor
                    WHERE source_type = :sourceType
                      AND source_key  = :sourceKey
                      AND revoked_at IS NULL
                    """,
                    new MapSqlParameterSource()
                            .addValue("tenantId", tenantId)
                            .addValue("sourceType", normalizedType)
                            .addValue("sourceKey", sourceKey)
                            .addValue("actor", actor));

            if (updated == 0) {
                return null;
            }

            if ("DISCOVERY_MODEL".equals(normalizedType)) {
                jdbcTemplate.update("""
                        UPDATE software_instances si
                        SET software_identity_id = NULL
                        FROM cis ci, discovery_models dm
                        WHERE si.ci_id = ci.id
                          AND si.discovery_model_id = dm.id
                          AND dm.primary_key = :sourceKey
                        """,
                        new MapSqlParameterSource()
                                .addValue("tenantId", tenantId)
                                .addValue("sourceKey", sourceKey));
            } else {
                String[] parts = parsePackageKey(sourceKey);
                jdbcTemplate.update("""
                        UPDATE inventory_components
                        SET software_identity_id = NULL
                        WHERE ecosystem   = :ecosystem
                          AND package_name = :packageName
                          AND component_status = 'ACTIVE'
                        """,
                        new MapSqlParameterSource()
                                .addValue("tenantId", tenantId)
                                .addValue("ecosystem", parts[0])
                                .addValue("packageName", parts[1]));
            }
            return null;
        });
    }

    private String normalizeType(String sourceType) {
        // Accept both the short form (DISCOVERY_MODEL) and the quality-projection
        // form (CLUSTER_DISCOVERY_MODEL) — store the short form in the DB.
        if (sourceType == null) return "DISCOVERY_MODEL";
        return switch (sourceType) {
            case "CLUSTER_DISCOVERY_MODEL" -> "DISCOVERY_MODEL";
            case "CLUSTER_PACKAGE_PATTERN" -> "PACKAGE_PATTERN";
            default -> sourceType;
        };
    }

    /** Parses "ecosystem:package_name" cluster keys. */
    private String[] parsePackageKey(String sourceKey) {
        if (sourceKey == null) return new String[]{"", ""};
        int idx = sourceKey.indexOf(':');
        if (idx < 0) return new String[]{sourceKey, ""};
        return new String[]{sourceKey.substring(0, idx), sourceKey.substring(idx + 1)};
    }

    public record ClusterImpactResult(long affectedAssetCount, long affectedInstanceCount) {}
}
