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
                  AND nullif(trim(ic.normalized_version), '') IS NULL
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
                    "missing_component_normalized_version",
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

    public List<QualityIssueRecord> buildComponentMissingNormalizedNameIssues(UUID tenantId) {
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
                  AND nullif(trim(ic.normalized_name), '') IS NULL
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
                    "component_missing_normalized_name",
                    "component:" + support.stringValue(row.get("component_id")) + ":normalized-name",
                    support.severityForExposureIssue(openFindingCount, openVulnerabilityCount, "MEDIUM"),
                    "missing_component_normalized_name",
                    "Inventory component is missing a normalized name",
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

        // SBOM components grouped by (ecosystem, package_name) cluster.
        // One quality issue per cluster covers all assets/components with that package.
        String componentSql = """
                SELECT
                    ic.ecosystem || ':' || ic.package_name               AS source_key,
                    ic.ecosystem,
                    ic.package_name,
                    COUNT(DISTINCT ic.asset_id)                          AS affected_asset_count,
                    COUNT(ic.id)                                         AS affected_component_count,
                    MIN(lower(coalesce(u.ingestion_source_system, 'inventory'))) AS source_system,
                    MAX(ic.last_observed_at)                             AS last_observed_at,
                    COALESCE(SUM(f_agg.open_finding_count), 0)           AS open_finding_count,
                    COALESCE(SUM(f_agg.open_vulnerability_count), 0)     AS open_vulnerability_count
                FROM inventory_components ic
                LEFT JOIN sbom_uploads u ON u.id = ic.sbom_upload_id
                LEFT JOIN LATERAL (
                    SELECT COUNT(*)               AS open_finding_count,
                           COUNT(DISTINCT vulnerability_id) AS open_vulnerability_count
                    FROM findings
                    WHERE component_id = ic.id AND status = 'OPEN'
                ) f_agg ON true
                WHERE ic.tenant_id = :tenantId
                  AND ic.component_status = 'ACTIVE'
                  AND ic.software_identity_id IS NULL
                  AND NOT EXISTS (
                      SELECT 1 FROM software_identity_cluster_link cl
                      WHERE cl.tenant_id   = :tenantId
                        AND cl.source_type = 'PACKAGE_PATTERN'
                        AND cl.source_key  = ic.ecosystem || ':' || ic.package_name
                        AND cl.revoked_at IS NULL
                  )
                GROUP BY ic.ecosystem, ic.package_name
                HAVING COUNT(ic.id) > 0
                ORDER BY COUNT(ic.id) DESC, ic.package_name ASC
                """;
        for (Map<String, Object> row : jdbcTemplate.queryForList(componentSql, support.tenantParams(tenantId))) {
            long openFindingCount = support.longValue(row.get("open_finding_count"));
            long openVulnerabilityCount = support.longValue(row.get("open_vulnerability_count"));
            long affectedAssetCount = support.longValue(row.get("affected_asset_count"));
            long affectedComponentCount = support.longValue(row.get("affected_component_count"));
            String sourceKey = support.stringValue(row.get("source_key"));
            String ecosystem = support.stringValue(row.get("ecosystem"));
            String packageName = support.stringValue(row.get("package_name"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("clusterKey", sourceKey);
            evidence.put("packageName", packageName);
            evidence.put("ecosystem", ecosystem);
            issues.add(support.issue(
                    tenantId,
                    "NORMALIZATION",
                    "component_missing_software_identity",
                    "cluster-pkg:" + sourceKey,
                    support.severityForExposureIssue(openFindingCount, openVulnerabilityCount, "MEDIUM"),
                    "missing_software_identity",
                    "Software package cluster is missing a software identity",
                    "CLUSTER_PACKAGE_PATTERN",
                    sourceKey,
                    sourceKey,
                    affectedAssetCount + " asset" + (affectedAssetCount != 1 ? "s" : ""),
                    null,
                    null,
                    null,
                    null,
                    support.stringValue(row.get("source_system")),
                    ecosystem,
                    support.affectsActiveFindings(openFindingCount, openVulnerabilityCount),
                    affectedAssetCount,
                    affectedComponentCount,
                    openFindingCount,
                    openVulnerabilityCount,
                    support.instantValue(row.get("last_observed_at")),
                    support.instantValue(row.get("last_observed_at")),
                    evidence
            ));
        }

        // Host software instances grouped by discovery_model.primary_key cluster.
        // One quality issue per cluster covers all matching assets.
        String softwareSql = """
                SELECT
                    dm.primary_key                                       AS source_key,
                    COUNT(DISTINCT ci.asset_id)                         AS affected_asset_count,
                    COUNT(si.id)                                        AS affected_instance_count,
                    MIN(si.display_name)                                AS sample_display_name,
                    MIN(lower(coalesce(si.source_system, 'inventory'))) AS source_system,
                    MAX(si.last_scanned)                                AS last_scanned,
                    COALESCE(SUM(f_agg.open_finding_count), 0)          AS open_finding_count,
                    COALESCE(SUM(f_agg.open_vulnerability_count), 0)    AS open_vulnerability_count
                FROM software_instances si
                JOIN cis ci ON ci.id = si.ci_id
                JOIN discovery_models dm ON dm.id = si.discovery_model_id
                LEFT JOIN LATERAL (
                    SELECT COUNT(*)               AS open_finding_count,
                           COUNT(DISTINCT vulnerability_id) AS open_vulnerability_count
                    FROM findings
                    WHERE asset_id = ci.asset_id AND status = 'OPEN'
                ) f_agg ON true
                WHERE si.tenant_id = :tenantId
                  AND si.active_install = true
                  AND si.software_identity_id IS NULL
                  AND si.inventory_component_id IS NULL
                  AND NOT EXISTS (
                      SELECT 1 FROM software_identity_cluster_link cl
                      WHERE cl.tenant_id   = :tenantId
                        AND cl.source_type = 'DISCOVERY_MODEL'
                        AND cl.source_key  = dm.primary_key
                        AND cl.revoked_at IS NULL
                  )
                GROUP BY dm.id, dm.primary_key
                HAVING COUNT(si.id) > 0
                ORDER BY COUNT(si.id) DESC, dm.primary_key ASC
                """;
        for (Map<String, Object> row : jdbcTemplate.queryForList(softwareSql, support.tenantParams(tenantId))) {
            long openFindingCount = support.longValue(row.get("open_finding_count"));
            long openVulnerabilityCount = support.longValue(row.get("open_vulnerability_count"));
            long affectedAssetCount = support.longValue(row.get("affected_asset_count"));
            long affectedInstanceCount = support.longValue(row.get("affected_instance_count"));
            String sourceKey = support.stringValue(row.get("source_key"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("clusterKey", sourceKey);
            evidence.put("sampleDisplayName", support.stringValue(row.get("sample_display_name")));
            issues.add(support.issue(
                    tenantId,
                    "NORMALIZATION",
                    "component_missing_software_identity",
                    "cluster-dm:" + sourceKey,
                    openFindingCount > 0 ? "MEDIUM" : "LOW",
                    "missing_software_identity",
                    "Host software cluster is missing a software identity",
                    "CLUSTER_DISCOVERY_MODEL",
                    sourceKey,
                    sourceKey,
                    affectedAssetCount + " asset" + (affectedAssetCount != 1 ? "s" : ""),
                    null,
                    null,
                    null,
                    "HOST",
                    support.stringValue(row.get("source_system")),
                    null,
                    support.affectsActiveFindings(openFindingCount, openVulnerabilityCount),
                    affectedAssetCount,
                    affectedInstanceCount,
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
        // Grouped by discovery_model.primary_key so one issue covers all assets affected
        // by the same genuinely uncertain model. Only fires when the source explicitly signals
        // uncertainty: dm.low_confidence = true (set by ServiceNow/ML) or dm.normalization_status
        // is a non-approved value. dm.approved is intentionally excluded — it defaults to false
        // for every ingested model and is never auto-set, so using it would surface all software
        // regardless of match confidence.
        String sql = """
                SELECT
                    dm.primary_key                                       AS source_key,
                    dm.normalization_status,
                    dm.approved,
                    dm.low_confidence,
                    COUNT(DISTINCT ci.asset_id)                         AS affected_asset_count,
                    COUNT(si.id)                                        AS affected_instance_count,
                    MIN(si.display_name)                                AS sample_display_name,
                    MIN(lower(coalesce(si.source_system, 'inventory'))) AS source_system,
                    MAX(si.last_scanned)                                AS last_scanned,
                    COALESCE(SUM(f_agg.open_finding_count), 0)          AS open_finding_count,
                    COALESCE(SUM(f_agg.open_vulnerability_count), 0)    AS open_vulnerability_count
                FROM software_instances si
                JOIN cis ci ON ci.id = si.ci_id
                JOIN discovery_models dm ON dm.id = si.discovery_model_id
                LEFT JOIN LATERAL (
                    SELECT COUNT(*)               AS open_finding_count,
                           COUNT(DISTINCT vulnerability_id) AS open_vulnerability_count
                    FROM findings
                    WHERE asset_id = ci.asset_id AND status = 'OPEN'
                ) f_agg ON true
                WHERE si.tenant_id = :tenantId
                  AND si.active_install = true
                  AND (
                    dm.low_confidence = true
                    OR (
                        dm.normalization_status IS NOT NULL
                        AND lower(dm.normalization_status) <> 'approved'
                    )
                  )
                  AND NOT EXISTS (
                      SELECT 1 FROM software_identity_cluster_link cl
                      WHERE cl.tenant_id   = :tenantId
                        AND cl.source_type = 'DISCOVERY_MODEL'
                        AND cl.source_key  = dm.primary_key
                        AND cl.revoked_at IS NULL
                  )
                GROUP BY dm.id, dm.primary_key, dm.normalization_status, dm.approved, dm.low_confidence
                HAVING COUNT(si.id) > 0
                ORDER BY COUNT(si.id) DESC, dm.primary_key ASC
                """;
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : jdbcTemplate.queryForList(sql, support.tenantParams(tenantId))) {
            long openFindingCount = support.longValue(row.get("open_finding_count"));
            long openVulnerabilityCount = support.longValue(row.get("open_vulnerability_count"));
            long affectedAssetCount = support.longValue(row.get("affected_asset_count"));
            long affectedInstanceCount = support.longValue(row.get("affected_instance_count"));
            String sourceKey = support.stringValue(row.get("source_key"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("clusterKey", sourceKey);
            evidence.put("sampleDisplayName", support.stringValue(row.get("sample_display_name")));
            evidence.put("normalizationStatus", support.stringValue(row.get("normalization_status")));
            evidence.put("approved", support.boolValue(row.get("approved")));
            evidence.put("lowConfidence", support.boolValue(row.get("low_confidence")));
            issues.add(support.issue(
                    tenantId,
                    "NORMALIZATION",
                    "host_discovery_model_review",
                    "cluster-dm:" + sourceKey + ":review",
                    support.severityForExposureIssue(openFindingCount, openVulnerabilityCount, "MEDIUM"),
                    "discovery_model_requires_review",
                    "Host discovery model normalization needs review",
                    "CLUSTER_DISCOVERY_MODEL",
                    sourceKey,
                    sourceKey,
                    affectedAssetCount + " asset" + (affectedAssetCount != 1 ? "s" : ""),
                    null,
                    null,
                    null,
                    "HOST",
                    support.stringValue(row.get("source_system")),
                    null,
                    support.affectsActiveFindings(openFindingCount, openVulnerabilityCount),
                    affectedAssetCount,
                    affectedInstanceCount,
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
