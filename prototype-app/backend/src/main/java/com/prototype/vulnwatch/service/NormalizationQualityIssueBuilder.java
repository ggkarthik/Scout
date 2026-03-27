package com.prototype.vulnwatch.service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class NormalizationQualityIssueBuilder {

    private static final double LOW_CONFIDENCE_ALIAS_THRESHOLD = HostInventoryReviewEvaluator.LOW_CONFIDENCE_ALIAS_THRESHOLD;

    private final NamedParameterJdbcTemplate jdbcTemplate;
    private final QualityIssueJdbcSupport support;

    public NormalizationQualityIssueBuilder(
            NamedParameterJdbcTemplate jdbcTemplate,
            QualityIssueJdbcSupport support
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.support = support;
    }

    public List<QualityIssueRecord> buildComponentMissingVersionIssues(UUID tenantId) {
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
                    ic.last_observed_at,
                    coalesce((
                        SELECT count(*)
                        FROM findings f
                        WHERE f.component_id = ic.id
                          AND f.status = 'OPEN'
                    ), 0) AS open_finding_count,
                    coalesce((
                        SELECT count(DISTINCT state.vulnerability_id)
                        FROM component_vulnerability_states state
                        WHERE state.component_id = ic.id
                    ), 0) AS open_vulnerability_count
                FROM inventory_components ic
                JOIN assets a ON a.id = ic.asset_id
                LEFT JOIN sbom_uploads u ON u.id = ic.sbom_upload_id
                WHERE ic.tenant_id = :tenantId
                  AND ic.component_status = 'ACTIVE'
                  AND coalesce(nullif(trim(ic.version), ''), nullif(trim(ic.normalized_version), '')) IS NULL
                ORDER BY ic.last_observed_at DESC
                """;
        List<Map<String, Object>> rows = jdbcTemplate.queryForList(sql, support.tenantParams(tenantId));
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : rows) {
            long openFindingCount = support.longValue(row.get("open_finding_count"));
            long openVulnerabilityCount = support.longValue(row.get("open_vulnerability_count"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("packageName", support.stringValue(row.get("package_name")));
            evidence.put("assetName", support.stringValue(row.get("asset_name")));
            evidence.put("assetIdentifier", support.stringValue(row.get("asset_identifier")));
            issues.add(support.issue(
                    tenantId,
                    "NORMALIZATION",
                    "component_missing_version",
                    "component:" + support.stringValue(row.get("component_id")),
                    support.severityForExposureIssue(openFindingCount, openVulnerabilityCount, "MEDIUM"),
                    "missing_component_version",
                    "Inventory component is missing a normalized version",
                    "INVENTORY_COMPONENT",
                    support.stringValue(row.get("component_id")),
                    support.stringValue(row.get("package_name")),
                    support.stringValue(row.get("asset_name")) + " (" + support.stringValue(row.get("asset_identifier")) + ")",
                    support.uuidValue(row.get("asset_id")),
                    support.uuidValue(row.get("component_id")),
                    null,
                    support.stringValue(row.get("asset_type")),
                    support.stringValue(row.get("source_system")),
                    support.stringValue(row.get("ecosystem")),
                    support.affectsActiveFindings(openFindingCount, openVulnerabilityCount),
                    1,
                    1,
                    openFindingCount,
                    openVulnerabilityCount,
                    support.instantValue(row.get("last_observed_at")),
                    support.instantValue(row.get("last_observed_at")),
                    evidence
            ));
        }
        return issues;
    }

    public List<QualityIssueRecord> buildComponentMissingSoftwareIdentityIssues(UUID tenantId) {
        List<QualityIssueRecord> issues = new ArrayList<>();

        String componentSql = """
                SELECT
                    ic.id AS component_id,
                    ic.asset_id,
                    a.name AS asset_name,
                    a.identifier AS asset_identifier,
                    a.type::text AS asset_type,
                    lower(coalesce(u.ingestion_source_system, 'inventory')) AS source_system,
                    ic.ecosystem,
                    ic.package_name,
                    ic.last_observed_at,
                    coalesce((
                        SELECT count(*)
                        FROM findings f
                        WHERE f.component_id = ic.id
                          AND f.status = 'OPEN'
                    ), 0) AS open_finding_count,
                    coalesce((
                        SELECT count(DISTINCT state.vulnerability_id)
                        FROM component_vulnerability_states state
                        WHERE state.component_id = ic.id
                    ), 0) AS open_vulnerability_count
                FROM inventory_components ic
                JOIN assets a ON a.id = ic.asset_id
                LEFT JOIN sbom_uploads u ON u.id = ic.sbom_upload_id
                WHERE ic.tenant_id = :tenantId
                  AND ic.component_status = 'ACTIVE'
                  AND ic.software_identity_id IS NULL
                ORDER BY ic.last_observed_at DESC
                """;
        for (Map<String, Object> row : jdbcTemplate.queryForList(componentSql, support.tenantParams(tenantId))) {
            long openFindingCount = support.longValue(row.get("open_finding_count"));
            long openVulnerabilityCount = support.longValue(row.get("open_vulnerability_count"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("packageName", support.stringValue(row.get("package_name")));
            evidence.put("assetName", support.stringValue(row.get("asset_name")));
            evidence.put("assetIdentifier", support.stringValue(row.get("asset_identifier")));
            issues.add(support.issue(
                    tenantId,
                    "NORMALIZATION",
                    "component_missing_software_identity",
                    "component:" + support.stringValue(row.get("component_id")),
                    support.severityForExposureIssue(openFindingCount, openVulnerabilityCount, "MEDIUM"),
                    "missing_software_identity",
                    "Inventory component is missing a software identity",
                    "INVENTORY_COMPONENT",
                    support.stringValue(row.get("component_id")),
                    support.stringValue(row.get("package_name")),
                    support.stringValue(row.get("asset_name")) + " (" + support.stringValue(row.get("asset_identifier")) + ")",
                    support.uuidValue(row.get("asset_id")),
                    support.uuidValue(row.get("component_id")),
                    null,
                    support.stringValue(row.get("asset_type")),
                    support.stringValue(row.get("source_system")),
                    support.stringValue(row.get("ecosystem")),
                    support.affectsActiveFindings(openFindingCount, openVulnerabilityCount),
                    1,
                    1,
                    openFindingCount,
                    openVulnerabilityCount,
                    support.instantValue(row.get("last_observed_at")),
                    support.instantValue(row.get("last_observed_at")),
                    evidence
            ));
        }

        String softwareSql = """
                SELECT
                    si.id AS software_instance_id,
                    ci.asset_id,
                    a.name AS asset_name,
                    a.identifier AS asset_identifier,
                    a.type::text AS asset_type,
                    lower(coalesce(si.source_system, 'inventory')) AS source_system,
                    si.display_name,
                    si.last_scanned,
                    coalesce((
                        SELECT count(*)
                        FROM findings f
                        WHERE f.asset_id = a.id
                          AND f.status = 'OPEN'
                    ), 0) AS open_finding_count,
                    coalesce((
                        SELECT count(DISTINCT f.vulnerability_id)
                        FROM findings f
                        WHERE f.asset_id = a.id
                          AND f.status = 'OPEN'
                    ), 0) AS open_vulnerability_count
                FROM software_instances si
                JOIN cis ci ON ci.id = si.ci_id
                JOIN assets a ON a.id = ci.asset_id
                WHERE si.tenant_id = :tenantId
                  AND si.active_install = true
                  AND si.software_identity_id IS NULL
                  AND si.inventory_component_id IS NULL
                ORDER BY si.last_scanned DESC NULLS LAST, si.display_name ASC
                """;
        for (Map<String, Object> row : jdbcTemplate.queryForList(softwareSql, support.tenantParams(tenantId))) {
            long openFindingCount = support.longValue(row.get("open_finding_count"));
            long openVulnerabilityCount = support.longValue(row.get("open_vulnerability_count"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("displayName", support.stringValue(row.get("display_name")));
            evidence.put("assetName", support.stringValue(row.get("asset_name")));
            evidence.put("assetIdentifier", support.stringValue(row.get("asset_identifier")));
            issues.add(support.issue(
                    tenantId,
                    "NORMALIZATION",
                    "component_missing_software_identity",
                    "software-instance:" + support.stringValue(row.get("software_instance_id")),
                    openFindingCount > 0 ? "MEDIUM" : "LOW",
                    "missing_software_identity",
                    "Host software instance is missing a software identity",
                    "SOFTWARE_INSTANCE",
                    support.stringValue(row.get("software_instance_id")),
                    support.stringValue(row.get("display_name")),
                    support.stringValue(row.get("asset_name")) + " (" + support.stringValue(row.get("asset_identifier")) + ")",
                    support.uuidValue(row.get("asset_id")),
                    null,
                    null,
                    support.stringValue(row.get("asset_type")),
                    support.stringValue(row.get("source_system")),
                    null,
                    support.affectsActiveFindings(openFindingCount, openVulnerabilityCount),
                    1,
                    0,
                    openFindingCount,
                    openVulnerabilityCount,
                    support.instantValue(row.get("last_scanned")),
                    support.instantValue(row.get("last_scanned")),
                    evidence
            ));
        }

        return issues;
    }

    public List<QualityIssueRecord> buildHostLowConfidenceAliasIssues(UUID tenantId) {
        String sql = """
                SELECT
                    alias.id AS alias_id,
                    ci.asset_id,
                    a.name AS asset_name,
                    a.identifier AS asset_identifier,
                    a.type::text AS asset_type,
                    lower(alias.source_system) AS source_system,
                    alias.alias_name,
                    alias.confidence,
                    alias.last_seen_at,
                    coalesce((
                        SELECT count(*)
                        FROM findings f
                        WHERE f.asset_id = a.id
                          AND f.status = 'OPEN'
                    ), 0) AS open_finding_count,
                    coalesce((
                        SELECT count(DISTINCT f.vulnerability_id)
                        FROM findings f
                        WHERE f.asset_id = a.id
                          AND f.status = 'OPEN'
                    ), 0) AS open_vulnerability_count
                FROM ci_aliases alias
                JOIN cis ci ON ci.id = alias.ci_id
                JOIN assets a ON a.id = ci.asset_id
                WHERE alias.tenant_id = :tenantId
                  AND alias.confidence IS NOT NULL
                  AND alias.confidence < :lowConfidence
                ORDER BY alias.last_seen_at DESC
                """;
        MapSqlParameterSource params = support.tenantParams(tenantId).addValue("lowConfidence", LOW_CONFIDENCE_ALIAS_THRESHOLD);
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : jdbcTemplate.queryForList(sql, params)) {
            long openFindingCount = support.longValue(row.get("open_finding_count"));
            long openVulnerabilityCount = support.longValue(row.get("open_vulnerability_count"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("aliasName", support.stringValue(row.get("alias_name")));
            evidence.put("confidence", support.doubleValue(row.get("confidence")));
            issues.add(support.issue(
                    tenantId,
                    "NORMALIZATION",
                    "host_low_confidence_alias",
                    "alias:" + support.stringValue(row.get("alias_id")),
                    openFindingCount > 0 ? "MEDIUM" : "LOW",
                    "ci_alias_confidence_below_threshold",
                    "Host alias confidence is below the approval threshold",
                    "CI_ALIAS",
                    support.stringValue(row.get("alias_id")),
                    support.stringValue(row.get("alias_name")),
                    support.stringValue(row.get("asset_name")) + " (" + support.stringValue(row.get("asset_identifier")) + ")",
                    support.uuidValue(row.get("asset_id")),
                    null,
                    null,
                    support.stringValue(row.get("asset_type")),
                    support.stringValue(row.get("source_system")),
                    null,
                    support.affectsActiveFindings(openFindingCount, openVulnerabilityCount),
                    1,
                    0,
                    openFindingCount,
                    openVulnerabilityCount,
                    support.instantValue(row.get("last_seen_at")),
                    support.instantValue(row.get("last_seen_at")),
                    evidence
            ));
        }
        return issues;
    }

    public List<QualityIssueRecord> buildHostDiscoveryModelReviewIssues(UUID tenantId) {
        String sql = """
                SELECT
                    si.id AS software_instance_id,
                    si.inventory_component_id AS component_id,
                    ci.asset_id,
                    a.name AS asset_name,
                    a.identifier AS asset_identifier,
                    a.type::text AS asset_type,
                    lower(coalesce(si.source_system, 'inventory')) AS source_system,
                    si.display_name,
                    dm.primary_key,
                    dm.normalization_status,
                    dm.approved,
                    dm.low_confidence,
                    si.last_scanned,
                    coalesce((
                        SELECT count(*)
                        FROM findings f
                        WHERE (
                            si.inventory_component_id IS NOT NULL
                            AND f.component_id = si.inventory_component_id
                            AND f.status = 'OPEN'
                        ) OR (
                            si.inventory_component_id IS NULL
                            AND f.asset_id = a.id
                            AND f.status = 'OPEN'
                        )
                    ), 0) AS open_finding_count,
                    coalesce((
                        SELECT count(DISTINCT f.vulnerability_id)
                        FROM findings f
                        WHERE (
                            si.inventory_component_id IS NOT NULL
                            AND f.component_id = si.inventory_component_id
                            AND f.status = 'OPEN'
                        ) OR (
                            si.inventory_component_id IS NULL
                            AND f.asset_id = a.id
                            AND f.status = 'OPEN'
                        )
                    ), 0) AS open_vulnerability_count
                FROM software_instances si
                JOIN cis ci ON ci.id = si.ci_id
                JOIN assets a ON a.id = ci.asset_id
                JOIN discovery_models dm ON dm.id = si.discovery_model_id
                WHERE si.tenant_id = :tenantId
                  AND si.active_install = true
                  AND (
                    dm.low_confidence = true
                    OR dm.approved = false
                    OR (
                        dm.normalization_status IS NOT NULL
                        AND lower(dm.normalization_status) <> 'approved'
                    )
                  )
                ORDER BY si.last_scanned DESC NULLS LAST, si.display_name ASC
                """;
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : jdbcTemplate.queryForList(sql, support.tenantParams(tenantId))) {
            long openFindingCount = support.longValue(row.get("open_finding_count"));
            long openVulnerabilityCount = support.longValue(row.get("open_vulnerability_count"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("displayName", support.stringValue(row.get("display_name")));
            evidence.put("discoveryModelKey", support.stringValue(row.get("primary_key")));
            evidence.put("normalizationStatus", support.stringValue(row.get("normalization_status")));
            evidence.put("approved", support.boolValue(row.get("approved")));
            evidence.put("lowConfidence", support.boolValue(row.get("low_confidence")));
            issues.add(support.issue(
                    tenantId,
                    "NORMALIZATION",
                    "host_discovery_model_review",
                    "software-instance:" + support.stringValue(row.get("software_instance_id")) + ":discovery-model",
                    support.severityForExposureIssue(openFindingCount, openVulnerabilityCount, "MEDIUM"),
                    "discovery_model_requires_review",
                    "Host discovery model normalization needs review",
                    "SOFTWARE_INSTANCE",
                    support.stringValue(row.get("software_instance_id")),
                    support.stringValue(row.get("display_name")),
                    support.stringValue(row.get("asset_name")) + " (" + support.stringValue(row.get("asset_identifier")) + ")",
                    support.uuidValue(row.get("asset_id")),
                    support.uuidValue(row.get("component_id")),
                    null,
                    support.stringValue(row.get("asset_type")),
                    support.stringValue(row.get("source_system")),
                    null,
                    support.affectsActiveFindings(openFindingCount, openVulnerabilityCount),
                    1,
                    row.get("component_id") == null ? 0 : 1,
                    openFindingCount,
                    openVulnerabilityCount,
                    support.instantValue(row.get("last_scanned")),
                    support.instantValue(row.get("last_scanned")),
                    evidence
            ));
        }
        return issues;
    }

    public List<QualityIssueRecord> buildVulnerabilityTargetIdentityUnresolvedIssues(UUID tenantId) {
        String sql = """
                SELECT
                    vt.id AS target_id,
                    vt.vulnerability_id,
                    v.external_id,
                    lower(coalesce(vt.source, 'unknown')) AS source_system,
                    vt.ecosystem,
                    vt.package_name,
                    vt.normalized_target_key,
                    vt.updated_at,
                    coalesce((
                        SELECT count(*)
                        FROM findings f
                        WHERE f.vulnerability_id = vt.vulnerability_id
                          AND f.status = 'OPEN'
                    ), 0) AS open_finding_count
                FROM vulnerability_targets vt
                JOIN vulnerabilities v ON v.id = vt.vulnerability_id
                WHERE vt.software_identity_id IS NULL
                  AND vt.target_type IN ('PURL', 'COORD', 'ADVISORY_PACKAGE')
                ORDER BY vt.updated_at DESC
                """;
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : jdbcTemplate.queryForList(sql, support.tenantParams(tenantId))) {
            long openFindingCount = support.longValue(row.get("open_finding_count"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("normalizedTargetKey", support.stringValue(row.get("normalized_target_key")));
            evidence.put("packageName", support.stringValue(row.get("package_name")));
            evidence.put("externalId", support.stringValue(row.get("external_id")));
            issues.add(support.issue(
                    tenantId,
                    "NORMALIZATION",
                    "vulnerability_target_identity_unresolved",
                    "vuln-target:" + support.stringValue(row.get("target_id")),
                    openFindingCount > 0 ? "HIGH" : "MEDIUM",
                    "vulnerability_target_missing_software_identity",
                    "Vulnerability target could not resolve to a software identity",
                    "VULNERABILITY_TARGET",
                    support.stringValue(row.get("target_id")),
                    support.stringValue(row.get("external_id")),
                    support.stringValue(row.get("package_name")),
                    null,
                    null,
                    null,
                    support.uuidValue(row.get("vulnerability_id")),
                    null,
                    support.stringValue(row.get("source_system")),
                    support.stringValue(row.get("ecosystem")),
                    openFindingCount > 0,
                    0,
                    0,
                    openFindingCount,
                    openFindingCount > 0 ? 1 : 0,
                    support.instantValue(row.get("updated_at")),
                    support.instantValue(row.get("updated_at")),
                    evidence
            ));
        }
        return issues;
    }

    public List<QualityIssueRecord> buildVexProductKeyUnresolvedIssues(UUID tenantId) {
        String sql = """
                SELECT
                    va.id AS assertion_id,
                    va.vulnerability_id,
                    v.external_id,
                    lower(coalesce(va.source_system, 'unknown')) AS source_system,
                    va.provider,
                    va.ecosystem,
                    va.package_name,
                    va.normalized_product_key,
                    va.updated_at,
                    coalesce((
                        SELECT count(*)
                        FROM findings f
                        WHERE f.vulnerability_id = va.vulnerability_id
                          AND f.status = 'OPEN'
                    ), 0) AS open_finding_count
                FROM vex_assertions va
                JOIN vulnerabilities v ON v.id = va.vulnerability_id
                WHERE va.software_identity_id IS NULL
                  AND trim(coalesce(va.normalized_product_key, '')) <> ''
                ORDER BY va.updated_at DESC
                """;
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : jdbcTemplate.queryForList(sql, support.tenantParams(tenantId))) {
            long openFindingCount = support.longValue(row.get("open_finding_count"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("provider", support.stringValue(row.get("provider")));
            evidence.put("normalizedProductKey", support.stringValue(row.get("normalized_product_key")));
            evidence.put("packageName", support.stringValue(row.get("package_name")));
            issues.add(support.issue(
                    tenantId,
                    "NORMALIZATION",
                    "vex_product_key_unresolved",
                    "vex-assertion:" + support.stringValue(row.get("assertion_id")),
                    openFindingCount > 0 ? "HIGH" : "MEDIUM",
                    "vex_assertion_missing_software_identity",
                    "VEX product key could not resolve to a software identity",
                    "VEX_ASSERTION",
                    support.stringValue(row.get("assertion_id")),
                    support.stringValue(row.get("external_id")),
                    support.stringValue(row.get("package_name")),
                    null,
                    null,
                    null,
                    support.uuidValue(row.get("vulnerability_id")),
                    null,
                    support.stringValue(row.get("source_system")),
                    support.stringValue(row.get("ecosystem")),
                    openFindingCount > 0,
                    0,
                    0,
                    openFindingCount,
                    openFindingCount > 0 ? 1 : 0,
                    support.instantValue(row.get("updated_at")),
                    support.instantValue(row.get("updated_at")),
                    evidence
            ));
        }
        return issues;
    }
}
