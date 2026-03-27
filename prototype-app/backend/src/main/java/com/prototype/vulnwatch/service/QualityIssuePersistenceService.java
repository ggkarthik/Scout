package com.prototype.vulnwatch.service;

import java.sql.Timestamp;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class QualityIssuePersistenceService {

    private final NamedParameterJdbcTemplate jdbcTemplate;

    public QualityIssuePersistenceService(NamedParameterJdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public void upsertRows(List<QualityIssueRecord> issues) {
        if (issues == null || issues.isEmpty()) {
            return;
        }
        String sql = """
                INSERT INTO quality_issue_projection (
                    id,
                    tenant_id,
                    issue_key,
                    domain,
                    issue_type,
                    severity,
                    reason_code,
                    source_object_type,
                    source_object_id,
                    asset_id,
                    component_id,
                    software_identity_id,
                    vulnerability_id,
                    sync_run_id,
                    title,
                    primary_label,
                    secondary_label,
                    asset_type,
                    source_system,
                    ecosystem,
                    affects_active_findings,
                    affected_asset_count,
                    affected_component_count,
                    open_finding_count,
                    open_vulnerability_count,
                    first_seen_at,
                    last_seen_at,
                    last_computed_at,
                    evidence_json,
                    drilldown_json
                )
                VALUES (
                    :id,
                    :tenantId,
                    :issueKey,
                    :domain,
                    :issueType,
                    :severity,
                    :reasonCode,
                    :sourceObjectType,
                    :sourceObjectId,
                    :assetId,
                    :componentId,
                    :softwareIdentityId,
                    :vulnerabilityId,
                    :syncRunId,
                    :title,
                    :primaryLabel,
                    :secondaryLabel,
                    :assetType,
                    :sourceSystem,
                    :ecosystem,
                    :affectsActiveFindings,
                    :affectedAssetCount,
                    :affectedComponentCount,
                    :openFindingCount,
                    :openVulnerabilityCount,
                    :firstSeenAt,
                    :lastSeenAt,
                    :lastComputedAt,
                    cast(:evidenceJson as jsonb),
                    cast(:drilldownJson as jsonb)
                )
                ON CONFLICT (id) DO UPDATE SET
                    id = EXCLUDED.id,
                    tenant_id = EXCLUDED.tenant_id,
                    issue_key = EXCLUDED.issue_key,
                    domain = EXCLUDED.domain,
                    issue_type = EXCLUDED.issue_type,
                    severity = EXCLUDED.severity,
                    reason_code = EXCLUDED.reason_code,
                    source_object_type = EXCLUDED.source_object_type,
                    source_object_id = EXCLUDED.source_object_id,
                    asset_id = EXCLUDED.asset_id,
                    component_id = EXCLUDED.component_id,
                    software_identity_id = EXCLUDED.software_identity_id,
                    vulnerability_id = EXCLUDED.vulnerability_id,
                    sync_run_id = EXCLUDED.sync_run_id,
                    title = EXCLUDED.title,
                    primary_label = EXCLUDED.primary_label,
                    secondary_label = EXCLUDED.secondary_label,
                    asset_type = EXCLUDED.asset_type,
                    source_system = EXCLUDED.source_system,
                    ecosystem = EXCLUDED.ecosystem,
                    affects_active_findings = EXCLUDED.affects_active_findings,
                    affected_asset_count = EXCLUDED.affected_asset_count,
                    affected_component_count = EXCLUDED.affected_component_count,
                    open_finding_count = EXCLUDED.open_finding_count,
                    open_vulnerability_count = EXCLUDED.open_vulnerability_count,
                    first_seen_at = quality_issue_projection.first_seen_at,
                    last_seen_at = EXCLUDED.last_seen_at,
                    last_computed_at = EXCLUDED.last_computed_at,
                    evidence_json = EXCLUDED.evidence_json,
                    drilldown_json = EXCLUDED.drilldown_json
                """;
        MapSqlParameterSource[] batch = issues.stream()
                .map(issue -> new MapSqlParameterSource()
                        .addValue("id", issue.id())
                        .addValue("tenantId", issue.tenantId())
                        .addValue("issueKey", issue.issueKey())
                        .addValue("domain", issue.domain())
                        .addValue("issueType", issue.issueType())
                        .addValue("severity", issue.severity())
                        .addValue("reasonCode", issue.reasonCode())
                        .addValue("sourceObjectType", issue.sourceObjectType())
                        .addValue("sourceObjectId", issue.sourceObjectId())
                        .addValue("assetId", issue.assetId())
                        .addValue("componentId", issue.componentId())
                        .addValue("softwareIdentityId", issue.softwareIdentityId())
                        .addValue("vulnerabilityId", issue.vulnerabilityId())
                        .addValue("syncRunId", issue.syncRunId())
                        .addValue("title", issue.title())
                        .addValue("primaryLabel", issue.primaryLabel())
                        .addValue("secondaryLabel", issue.secondaryLabel())
                        .addValue("assetType", issue.assetType())
                        .addValue("sourceSystem", issue.sourceSystem())
                        .addValue("ecosystem", issue.ecosystem())
                        .addValue("affectsActiveFindings", issue.affectsActiveFindings())
                        .addValue("affectedAssetCount", issue.affectedAssetCount())
                        .addValue("affectedComponentCount", issue.affectedComponentCount())
                        .addValue("openFindingCount", issue.openFindingCount())
                        .addValue("openVulnerabilityCount", issue.openVulnerabilityCount())
                        .addValue("firstSeenAt", Timestamp.from(issue.firstSeenAt()))
                        .addValue("lastSeenAt", Timestamp.from(issue.lastSeenAt()))
                        .addValue("lastComputedAt", Timestamp.from(issue.lastComputedAt()))
                        .addValue("evidenceJson", issue.evidenceJson())
                        .addValue("drilldownJson", issue.drilldownJson()))
                .toArray(MapSqlParameterSource[]::new);
        jdbcTemplate.batchUpdate(sql, batch);
    }

    public void deleteStaleRows(UUID tenantId, List<QualityIssueRecord> issues) {
        MapSqlParameterSource params = new MapSqlParameterSource().addValue("tenantId", tenantId);
        if (issues == null || issues.isEmpty()) {
            jdbcTemplate.update("DELETE FROM quality_issue_projection WHERE tenant_id = :tenantId", params);
            return;
        }
        List<String> issueKeys = issues.stream().map(QualityIssueRecord::issueKey).distinct().toList();
        params.addValue("issueKeys", issueKeys);
        jdbcTemplate.update("""
                DELETE FROM quality_issue_projection
                WHERE tenant_id = :tenantId
                  AND issue_key NOT IN (:issueKeys)
                """, params);
    }
}
