package com.prototype.vulnwatch.service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class VexQualityIssueBuilder {

    private final NamedParameterJdbcTemplate jdbcTemplate;
    private final QualityIssueJdbcSupport support;

    public VexQualityIssueBuilder(
            NamedParameterJdbcTemplate jdbcTemplate,
            QualityIssueJdbcSupport support
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.support = support;
    }

    public List<QualityIssueRecord> buildVendorOnlyVexCoverageIssues(UUID tenantId) {
        String sql = """
                SELECT
                    state.vulnerability_id,
                    v.external_id,
                    count(DISTINCT state.component_id) AS affected_component_count,
                    count(DISTINCT ic.asset_id) AS affected_asset_count,
                    max(state.last_evaluated_at) AS last_evaluated_at,
                    coalesce((
                        SELECT count(*)
                        FROM findings f
                        WHERE f.vulnerability_id = state.vulnerability_id
                          AND f.status = 'OPEN'
                    ), 0) AS open_finding_count
                FROM component_vulnerability_states state
                JOIN inventory_components ic ON ic.id = state.component_id
                JOIN vulnerabilities v ON v.id = state.vulnerability_id
                WHERE state.tenant_id = :tenantId
                  AND ic.component_status = 'ACTIVE'
                  AND state.matched_vex_assertion_id IS NULL
                  AND state.applicability_state IN ('APPLICABLE', 'UNKNOWN')
                  AND EXISTS (
                      SELECT 1
                      FROM vex_assertions va
                      WHERE va.vulnerability_id = state.vulnerability_id
                  )
                GROUP BY state.vulnerability_id, v.external_id
                HAVING count(DISTINCT state.component_id) >= 2
                ORDER BY max(state.last_evaluated_at) DESC
                """;
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : jdbcTemplate.queryForList(sql, support.tenantParams(tenantId))) {
            long openFindingCount = support.longValue(row.get("open_finding_count"));
            long affectedComponentCount = support.longValue(row.get("affected_component_count"));
            long affectedAssetCount = support.longValue(row.get("affected_asset_count"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("externalId", support.stringValue(row.get("external_id")));
            evidence.put("affectedComponentCount", affectedComponentCount);
            evidence.put("affectedAssetCount", affectedAssetCount);
            issues.add(support.issue(
                    tenantId,
                    "VEX",
                    "vendor_only_vex_coverage",
                    "vulnerability:" + support.stringValue(row.get("vulnerability_id")) + ":vendor-only-vex",
                    openFindingCount > 0 ? "HIGH" : "MEDIUM",
                    "vex_exists_but_no_exact_component_match",
                    "VEX exists only at vendor scope for this vulnerability",
                    "VULNERABILITY",
                    support.stringValue(row.get("vulnerability_id")),
                    support.stringValue(row.get("external_id")),
                    affectedComponentCount + " affected components",
                    null,
                    null,
                    null,
                    support.uuidValue(row.get("vulnerability_id")),
                    null,
                    "vendor_vex",
                    null,
                    openFindingCount > 0,
                    affectedAssetCount,
                    affectedComponentCount,
                    openFindingCount,
                    1,
                    support.instantValue(row.get("last_evaluated_at")),
                    support.instantValue(row.get("last_evaluated_at")),
                    evidence
            ));
        }
        return issues;
    }

    public List<QualityIssueRecord> buildAwaitingExactVexIssues(
            UUID tenantId,
            Set<UUID> vendorOnlyVulnerabilityIds,
            Set<String> conflictedPairs
    ) {
        String sql = """
                SELECT
                    state.component_id,
                    state.vulnerability_id,
                    ic.asset_id,
                    a.name AS asset_name,
                    a.identifier AS asset_identifier,
                    a.type::text AS asset_type,
                    lower(coalesce(u.ingestion_source_system, 'inventory')) AS source_system,
                    ic.ecosystem,
                    ic.package_name,
                    ic.version,
                    v.external_id,
                    state.last_evaluated_at,
                    coalesce((
                        SELECT count(*)
                        FROM findings f
                        WHERE f.component_id = state.component_id
                          AND f.vulnerability_id = state.vulnerability_id
                          AND f.status = 'OPEN'
                    ), 0) AS open_finding_count
                FROM component_vulnerability_states state
                JOIN inventory_components ic ON ic.id = state.component_id
                JOIN assets a ON a.id = ic.asset_id
                JOIN vulnerabilities v ON v.id = state.vulnerability_id
                LEFT JOIN sbom_uploads u ON u.id = ic.sbom_upload_id
                WHERE state.tenant_id = :tenantId
                  AND ic.component_status = 'ACTIVE'
                  AND state.applicability_state = 'APPLICABLE'
                  AND state.matched_vex_assertion_id IS NULL
                  AND lower(coalesce(state.impact_reason, '')) = 'awaiting_vex_assessment'
                ORDER BY state.last_evaluated_at DESC
                """;
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : jdbcTemplate.queryForList(sql, support.tenantParams(tenantId))) {
            UUID vulnerabilityId = support.uuidValue(row.get("vulnerability_id"));
            UUID componentId = support.uuidValue(row.get("component_id"));
            if (vendorOnlyVulnerabilityIds.contains(vulnerabilityId)
                    || conflictedPairs.contains(support.vexPairKey(componentId, vulnerabilityId))) {
                continue;
            }
            long openFindingCount = support.longValue(row.get("open_finding_count"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("externalId", support.stringValue(row.get("external_id")));
            evidence.put("packageName", support.stringValue(row.get("package_name")));
            evidence.put("version", support.stringValue(row.get("version")));
            issues.add(support.issue(
                    tenantId,
                    "VEX",
                    "awaiting_exact_vex",
                    "state:" + support.stringValue(row.get("component_id")) + ":" + support.stringValue(row.get("vulnerability_id")),
                    openFindingCount > 0 ? "HIGH" : "MEDIUM",
                    "awaiting_exact_vex_assessment",
                    "Component is awaiting exact VEX evidence",
                    "COMPONENT_VULNERABILITY_STATE",
                    support.stringValue(row.get("component_id")) + ":" + support.stringValue(row.get("vulnerability_id")),
                    support.stringValue(row.get("external_id")),
                    support.stringValue(row.get("package_name")) + " on " + support.stringValue(row.get("asset_name")),
                    support.uuidValue(row.get("asset_id")),
                    componentId,
                    null,
                    vulnerabilityId,
                    null,
                    support.stringValue(row.get("source_system")),
                    support.stringValue(row.get("ecosystem")),
                    openFindingCount > 0,
                    1,
                    1,
                    openFindingCount,
                    1,
                    support.instantValue(row.get("last_evaluated_at")),
                    support.instantValue(row.get("last_evaluated_at")),
                    evidence
            ));
        }
        return issues;
    }

    public List<QualityIssueRecord> buildStaleVexMatchIssues(UUID tenantId) {
        String sql = """
                SELECT
                    state.component_id,
                    state.vulnerability_id,
                    ic.asset_id,
                    a.name AS asset_name,
                    a.identifier AS asset_identifier,
                    a.type::text AS asset_type,
                    lower(coalesce(u.ingestion_source_system, 'inventory')) AS source_system,
                    ic.ecosystem,
                    ic.package_name,
                    ic.version,
                    v.external_id,
                    state.vex_provider,
                    state.last_evaluated_at,
                    coalesce((
                        SELECT count(*)
                        FROM findings f
                        WHERE f.component_id = state.component_id
                          AND f.vulnerability_id = state.vulnerability_id
                          AND f.status = 'OPEN'
                    ), 0) AS open_finding_count
                FROM component_vulnerability_states state
                JOIN inventory_components ic ON ic.id = state.component_id
                JOIN assets a ON a.id = ic.asset_id
                JOIN vulnerabilities v ON v.id = state.vulnerability_id
                LEFT JOIN sbom_uploads u ON u.id = ic.sbom_upload_id
                WHERE state.tenant_id = :tenantId
                  AND ic.component_status = 'ACTIVE'
                  AND state.matched_vex_assertion_id IS NOT NULL
                  AND upper(coalesce(state.vex_freshness, '')) = 'STALE'
                ORDER BY state.last_evaluated_at DESC
                """;
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : jdbcTemplate.queryForList(sql, support.tenantParams(tenantId))) {
            long openFindingCount = support.longValue(row.get("open_finding_count"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("externalId", support.stringValue(row.get("external_id")));
            evidence.put("packageName", support.stringValue(row.get("package_name")));
            evidence.put("vexProvider", support.stringValue(row.get("vex_provider")));
            issues.add(support.issue(
                    tenantId,
                    "VEX",
                    "stale_vex_match",
                    "state:" + support.stringValue(row.get("component_id")) + ":" + support.stringValue(row.get("vulnerability_id")) + ":stale-vex",
                    openFindingCount > 0 ? "HIGH" : "MEDIUM",
                    "matched_vex_assertion_is_stale",
                    "Component is matched to stale VEX evidence",
                    "COMPONENT_VULNERABILITY_STATE",
                    support.stringValue(row.get("component_id")) + ":" + support.stringValue(row.get("vulnerability_id")),
                    support.stringValue(row.get("external_id")),
                    support.stringValue(row.get("package_name")) + " on " + support.stringValue(row.get("asset_name")),
                    support.uuidValue(row.get("asset_id")),
                    support.uuidValue(row.get("component_id")),
                    null,
                    support.uuidValue(row.get("vulnerability_id")),
                    null,
                    support.stringValue(row.get("source_system")),
                    support.stringValue(row.get("ecosystem")),
                    openFindingCount > 0,
                    1,
                    1,
                    openFindingCount,
                    1,
                    support.instantValue(row.get("last_evaluated_at")),
                    support.instantValue(row.get("last_evaluated_at")),
                    evidence
            ));
        }
        return issues;
    }

    public List<QualityIssueRecord> buildOpenFindingConflictsWithVexIssues(UUID tenantId) {
        String sql = """
                SELECT
                    state.component_id,
                    state.vulnerability_id,
                    ic.asset_id,
                    a.name AS asset_name,
                    a.identifier AS asset_identifier,
                    a.type::text AS asset_type,
                    lower(coalesce(u.ingestion_source_system, 'inventory')) AS source_system,
                    ic.ecosystem,
                    ic.package_name,
                    ic.version,
                    v.external_id,
                    state.impact_state,
                    state.last_evaluated_at,
                    count(*) AS open_finding_count
                FROM component_vulnerability_states state
                JOIN findings f
                  ON f.component_id = state.component_id
                 AND f.vulnerability_id = state.vulnerability_id
                 AND f.status = 'OPEN'
                JOIN inventory_components ic ON ic.id = state.component_id
                JOIN assets a ON a.id = ic.asset_id
                JOIN vulnerabilities v ON v.id = state.vulnerability_id
                LEFT JOIN sbom_uploads u ON u.id = ic.sbom_upload_id
                WHERE state.tenant_id = :tenantId
                  AND ic.component_status = 'ACTIVE'
                  AND state.impact_state IN ('FIXED', 'NOT_IMPACTED')
                GROUP BY
                    state.component_id,
                    state.vulnerability_id,
                    ic.asset_id,
                    a.name,
                    a.identifier,
                    a.type,
                    u.ingestion_source_system,
                    ic.ecosystem,
                    ic.package_name,
                    ic.version,
                    v.external_id,
                    state.impact_state,
                    state.last_evaluated_at
                ORDER BY state.last_evaluated_at DESC
                """;
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : jdbcTemplate.queryForList(sql, support.tenantParams(tenantId))) {
            long openFindingCount = support.longValue(row.get("open_finding_count"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("externalId", support.stringValue(row.get("external_id")));
            evidence.put("packageName", support.stringValue(row.get("package_name")));
            evidence.put("impactState", support.stringValue(row.get("impact_state")));
            issues.add(support.issue(
                    tenantId,
                    "VEX",
                    "open_finding_conflicts_with_vex",
                    "state:" + support.stringValue(row.get("component_id")) + ":" + support.stringValue(row.get("vulnerability_id")) + ":finding-conflict",
                    "CRITICAL",
                    "open_finding_conflicts_with_vex_impact_state",
                    "Open finding conflicts with current VEX-driven impact state",
                    "FINDING",
                    support.stringValue(row.get("component_id")) + ":" + support.stringValue(row.get("vulnerability_id")),
                    support.stringValue(row.get("external_id")),
                    support.stringValue(row.get("package_name")) + " on " + support.stringValue(row.get("asset_name")),
                    support.uuidValue(row.get("asset_id")),
                    support.uuidValue(row.get("component_id")),
                    null,
                    support.uuidValue(row.get("vulnerability_id")),
                    null,
                    support.stringValue(row.get("source_system")),
                    support.stringValue(row.get("ecosystem")),
                    true,
                    1,
                    1,
                    openFindingCount,
                    1,
                    support.instantValue(row.get("last_evaluated_at")),
                    support.instantValue(row.get("last_evaluated_at")),
                    evidence
            ));
        }
        return issues;
    }
}
