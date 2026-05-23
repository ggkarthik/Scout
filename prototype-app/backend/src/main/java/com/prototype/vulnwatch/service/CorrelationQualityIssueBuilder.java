package com.prototype.vulnwatch.service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class CorrelationQualityIssueBuilder {

    private static final double LOW_CONFIDENCE_THRESHOLD = 0.65d;

    private final NamedParameterJdbcTemplate jdbcTemplate;
    private final QualityIssueJdbcSupport support;

    public CorrelationQualityIssueBuilder(
            NamedParameterJdbcTemplate jdbcTemplate,
            QualityIssueJdbcSupport support
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.support = support;
    }

    public List<QualityIssueRecord> buildComponentNoCorrelationCandidatesIssues(UUID tenantId, Set<UUID> suppressedComponentIds) {
        String sql = """
                SELECT
                    ic.id AS component_id,
                    ic.asset_id,
                    a.name AS asset_name,
                    a.identifier AS asset_identifier,
                    a.type::text AS asset_type,
                    lower(coalesce(u.ingestion_source_system, 'inventory')) AS source_system,
                    ic.ecosystem,
                    ic.package_name,
                    ic.version,
                    max(state.last_evaluated_at) AS last_evaluated_at,
                    count(DISTINCT state.vulnerability_id) AS open_vulnerability_count,
                    coalesce((
                        SELECT count(*)
                        FROM findings f
                        WHERE f.component_id = ic.id
                          AND f.status = 'OPEN'
                    ), 0) AS open_finding_count
                FROM component_vulnerability_states state
                JOIN inventory_components ic ON ic.id = state.component_id
                JOIN assets a ON a.id = ic.asset_id
                LEFT JOIN sbom_uploads u ON u.id = ic.sbom_upload_id
                WHERE ic.component_status = 'ACTIVE'
                  AND lower(coalesce(state.applicability_reason, '')) = 'no_candidates'
                  AND state.analyst_disposition IS NULL
                GROUP BY ic.id, ic.asset_id, a.name, a.identifier, a.type, u.ingestion_source_system, ic.ecosystem, ic.package_name, ic.version
                ORDER BY max(state.last_evaluated_at) DESC
                """;
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : jdbcTemplate.queryForList(sql, support.tenantParams(tenantId))) {
            UUID componentId = support.uuidValue(row.get("component_id"));
            if (suppressedComponentIds.contains(componentId)) {
                continue;
            }
            long openFindingCount = support.longValue(row.get("open_finding_count"));
            long openVulnerabilityCount = support.longValue(row.get("open_vulnerability_count"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("packageName", support.stringValue(row.get("package_name")));
            evidence.put("version", support.stringValue(row.get("version")));
            evidence.put("reason", "no_candidates");
            issues.add(support.issue(
                    tenantId,
                    "CORRELATION",
                    "component_no_correlation_candidates",
                    "component:" + support.stringValue(row.get("component_id")) + ":no-candidates",
                    support.severityForExposureIssue(openFindingCount, openVulnerabilityCount, "MEDIUM"),
                    "no_correlation_candidates",
                    "Component has no correlation candidates",
                    "INVENTORY_COMPONENT",
                    support.stringValue(row.get("component_id")),
                    support.stringValue(row.get("package_name")),
                    support.stringValue(row.get("asset_name")) + " (" + support.stringValue(row.get("asset_identifier")) + ")",
                    support.uuidValue(row.get("asset_id")),
                    componentId,
                    null,
                    support.stringValue(row.get("asset_type")),
                    support.stringValue(row.get("source_system")),
                    support.stringValue(row.get("ecosystem")),
                    support.affectsActiveFindings(openFindingCount, openVulnerabilityCount),
                    1,
                    1,
                    openFindingCount,
                    openVulnerabilityCount,
                    support.instantValue(row.get("last_evaluated_at")),
                    support.instantValue(row.get("last_evaluated_at")),
                    evidence
            ));
        }
        return issues;
    }

    public List<QualityIssueRecord> buildComponentFallbackOnlyCorrelationIssues(
            UUID tenantId,
            Set<UUID> suppressedComponentIds,
            Set<UUID> noCandidateComponentIds
    ) {
        String sql = """
                SELECT
                    ic.id AS component_id,
                    ic.asset_id,
                    a.name AS asset_name,
                    a.identifier AS asset_identifier,
                    a.type::text AS asset_type,
                    lower(coalesce(u.ingestion_source_system, 'inventory')) AS source_system,
                    ic.ecosystem,
                    ic.package_name,
                    ic.version,
                    max(state.last_evaluated_at) AS last_evaluated_at,
                    count(DISTINCT state.vulnerability_id) AS open_vulnerability_count,
                    count(*) FILTER (WHERE lower(coalesce(state.matched_by, '')) like '%fallback%') AS fallback_count,
                    count(*) AS total_state_count,
                    coalesce((
                        SELECT count(*)
                        FROM findings f
                        WHERE f.component_id = ic.id
                          AND f.status = 'OPEN'
                    ), 0) AS open_finding_count
                FROM component_vulnerability_states state
                JOIN inventory_components ic ON ic.id = state.component_id
                JOIN assets a ON a.id = ic.asset_id
                LEFT JOIN sbom_uploads u ON u.id = ic.sbom_upload_id
                WHERE ic.component_status = 'ACTIVE'
                  AND trim(coalesce(state.matched_by, '')) <> ''
                  AND state.analyst_disposition IS NULL
                GROUP BY ic.id, ic.asset_id, a.name, a.identifier, a.type, u.ingestion_source_system, ic.ecosystem, ic.package_name, ic.version
                HAVING count(*) FILTER (WHERE lower(coalesce(state.matched_by, '')) like '%fallback%') = count(*)
                   AND count(*) > 0
                ORDER BY max(state.last_evaluated_at) DESC
                """;
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : jdbcTemplate.queryForList(sql, support.tenantParams(tenantId))) {
            UUID componentId = support.uuidValue(row.get("component_id"));
            if (suppressedComponentIds.contains(componentId) || noCandidateComponentIds.contains(componentId)) {
                continue;
            }
            long openFindingCount = support.longValue(row.get("open_finding_count"));
            long openVulnerabilityCount = support.longValue(row.get("open_vulnerability_count"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("packageName", support.stringValue(row.get("package_name")));
            evidence.put("version", support.stringValue(row.get("version")));
            evidence.put("fallbackStates", support.longValue(row.get("fallback_count")));
            evidence.put("totalStates", support.longValue(row.get("total_state_count")));
            issues.add(support.issue(
                    tenantId,
                    "CORRELATION",
                    "component_fallback_only_correlation",
                    "component:" + support.stringValue(row.get("component_id")) + ":fallback-only",
                    openFindingCount > 0 ? "HIGH" : "MEDIUM",
                    "all_selected_matches_use_fallback_methods",
                    "Component correlation relies only on fallback matching",
                    "INVENTORY_COMPONENT",
                    support.stringValue(row.get("component_id")),
                    support.stringValue(row.get("package_name")),
                    support.stringValue(row.get("asset_name")) + " (" + support.stringValue(row.get("asset_identifier")) + ")",
                    support.uuidValue(row.get("asset_id")),
                    componentId,
                    null,
                    support.stringValue(row.get("asset_type")),
                    support.stringValue(row.get("source_system")),
                    support.stringValue(row.get("ecosystem")),
                    support.affectsActiveFindings(openFindingCount, openVulnerabilityCount),
                    1,
                    1,
                    openFindingCount,
                    openVulnerabilityCount,
                    support.instantValue(row.get("last_evaluated_at")),
                    support.instantValue(row.get("last_evaluated_at")),
                    evidence
            ));
        }
        return issues;
    }

    public List<QualityIssueRecord> buildComponentLowConfidenceMatchIssues(
            UUID tenantId,
            Set<UUID> suppressedComponentIds,
            Set<UUID> noCandidateComponentIds,
            Set<UUID> fallbackOnlyComponentIds
    ) {
        String sql = """
                SELECT
                    ic.id AS component_id,
                    ic.asset_id,
                    a.name AS asset_name,
                    a.identifier AS asset_identifier,
                    a.type::text AS asset_type,
                    lower(coalesce(u.ingestion_source_system, 'inventory')) AS source_system,
                    ic.ecosystem,
                    ic.package_name,
                    ic.version,
                    max(state.last_evaluated_at) AS last_evaluated_at,
                    min(state.confidence_score) AS min_confidence_score,
                    count(DISTINCT state.vulnerability_id) AS open_vulnerability_count,
                    coalesce((
                        SELECT count(*)
                        FROM findings f
                        WHERE f.component_id = ic.id
                          AND f.status = 'OPEN'
                    ), 0) AS open_finding_count
                FROM component_vulnerability_states state
                JOIN inventory_components ic ON ic.id = state.component_id
                JOIN assets a ON a.id = ic.asset_id
                LEFT JOIN sbom_uploads u ON u.id = ic.sbom_upload_id
                WHERE ic.component_status = 'ACTIVE'
                  AND state.confidence_score IS NOT NULL
                  AND state.confidence_score < :confidenceThreshold
                  AND trim(coalesce(state.matched_by, '')) <> ''
                  AND state.analyst_disposition IS NULL
                GROUP BY ic.id, ic.asset_id, a.name, a.identifier, a.type, u.ingestion_source_system, ic.ecosystem, ic.package_name, ic.version
                ORDER BY min(state.confidence_score) ASC, max(state.last_evaluated_at) DESC
                """;
        MapSqlParameterSource params = support.tenantParams(tenantId).addValue("confidenceThreshold", LOW_CONFIDENCE_THRESHOLD);
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : jdbcTemplate.queryForList(sql, params)) {
            UUID componentId = support.uuidValue(row.get("component_id"));
            if (suppressedComponentIds.contains(componentId)
                    || noCandidateComponentIds.contains(componentId)
                    || fallbackOnlyComponentIds.contains(componentId)) {
                continue;
            }
            long openFindingCount = support.longValue(row.get("open_finding_count"));
            long openVulnerabilityCount = support.longValue(row.get("open_vulnerability_count"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("packageName", support.stringValue(row.get("package_name")));
            evidence.put("version", support.stringValue(row.get("version")));
            evidence.put("minConfidenceScore", support.doubleValue(row.get("min_confidence_score")));
            evidence.put("threshold", LOW_CONFIDENCE_THRESHOLD);
            issues.add(support.issue(
                    tenantId,
                    "CORRELATION",
                    "component_low_confidence_match",
                    "component:" + support.stringValue(row.get("component_id")) + ":low-confidence",
                    openFindingCount > 0 ? "HIGH" : "MEDIUM",
                    "selected_match_confidence_below_threshold",
                    "Component correlation confidence is below the review threshold",
                    "INVENTORY_COMPONENT",
                    support.stringValue(row.get("component_id")),
                    support.stringValue(row.get("package_name")),
                    support.stringValue(row.get("asset_name")) + " (" + support.stringValue(row.get("asset_identifier")) + ")",
                    support.uuidValue(row.get("asset_id")),
                    componentId,
                    null,
                    support.stringValue(row.get("asset_type")),
                    support.stringValue(row.get("source_system")),
                    support.stringValue(row.get("ecosystem")),
                    support.affectsActiveFindings(openFindingCount, openVulnerabilityCount),
                    1,
                    1,
                    openFindingCount,
                    openVulnerabilityCount,
                    support.instantValue(row.get("last_evaluated_at")),
                    support.instantValue(row.get("last_evaluated_at")),
                    evidence
            ));
        }
        return issues;
    }
}
