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
public class LifecycleQualityIssueBuilder {

    private final NamedParameterJdbcTemplate jdbcTemplate;
    private final QualityIssueJdbcSupport support;

    public LifecycleQualityIssueBuilder(
            NamedParameterJdbcTemplate jdbcTemplate,
            QualityIssueJdbcSupport support
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.support = support;
    }

    public List<QualityIssueRecord> buildSoftwareIdentityNeedsEolMappingIssues(UUID tenantId) {
        String sql = """
                WITH exposure AS (
                    SELECT
                        ic.software_identity_id,
                        count(DISTINCT f.id) FILTER (WHERE f.status = 'OPEN') AS open_finding_count,
                        count(DISTINCT state.vulnerability_id) AS open_vulnerability_count
                    FROM inventory_components ic
                    LEFT JOIN findings f ON f.component_id = ic.id
                    LEFT JOIN component_vulnerability_states state ON state.component_id = ic.id
                    WHERE ic.component_status = 'ACTIVE'
                      AND ic.software_identity_id IS NOT NULL
                    GROUP BY ic.software_identity_id
                )
                SELECT
                    sis.software_identity_id,
                    sis.display_name,
                    sis.eol_slug,
                    sis.asset_count,
                    sis.component_count,
                    sis.version_count,
                    sis.last_observed_at,
                    CASE
                        WHEN coalesce(array_length(sis.asset_types, 1), 0) = 1 THEN sis.asset_types[1]
                        WHEN coalesce(array_length(sis.asset_types, 1), 0) > 1 THEN 'MULTIPLE'
                        ELSE NULL
                    END AS asset_type,
                    CASE
                        WHEN coalesce(array_length(sis.source_systems, 1), 0) = 1 THEN sis.source_systems[1]
                        WHEN coalesce(array_length(sis.source_systems, 1), 0) > 1 THEN 'multiple'
                        ELSE NULL
                    END AS source_system,
                    CASE
                        WHEN coalesce(array_length(sis.ecosystems, 1), 0) = 1 THEN sis.ecosystems[1]
                        WHEN coalesce(array_length(sis.ecosystems, 1), 0) > 1 THEN 'multiple'
                        ELSE NULL
                    END AS ecosystem,
                    coalesce(exposure.open_finding_count, 0) AS open_finding_count,
                    coalesce(exposure.open_vulnerability_count, 0) AS open_vulnerability_count
                FROM software_identity_summary sis
                LEFT JOIN exposure ON exposure.software_identity_id = sis.software_identity_id
                WHERE sis.needs_eol_mapping = true
                ORDER BY sis.last_observed_at DESC NULLS LAST, sis.display_name ASC
                """;
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : jdbcTemplate.queryForList(sql, support.tenantParams(tenantId))) {
            long openFindingCount = support.longValue(row.get("open_finding_count"));
            long openVulnerabilityCount = support.longValue(row.get("open_vulnerability_count"));
            long assetCount = support.longValue(row.get("asset_count"));
            long componentCount = support.longValue(row.get("component_count"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("displayName", support.stringValue(row.get("display_name")));
            evidence.put("versionCount", support.longValue(row.get("version_count")));
            issues.add(support.issue(
                    tenantId,
                    "EOL",
                    "software_identity_needs_eol_mapping",
                    "software-identity:" + support.stringValue(row.get("software_identity_id")) + ":needs-eol-mapping",
                    support.severityForExposureIssue(openFindingCount, openVulnerabilityCount, "MEDIUM"),
                    "missing_eol_slug_mapping",
                    "Software identity needs an EOL mapping",
                    "SOFTWARE_IDENTITY",
                    support.stringValue(row.get("software_identity_id")),
                    support.stringValue(row.get("display_name")),
                    "No mapped endoflife.date slug",
                    null,
                    null,
                    support.uuidValue(row.get("software_identity_id")),
                    null,
                    null,
                    support.stringValue(row.get("source_system")),
                    support.stringValue(row.get("ecosystem")),
                    support.affectsActiveFindings(openFindingCount, openVulnerabilityCount),
                    assetCount,
                    componentCount,
                    openFindingCount,
                    openVulnerabilityCount,
                    support.instantValue(row.get("last_observed_at")),
                    support.instantValue(row.get("last_observed_at")),
                    evidence
            ));
        }
        return issues;
    }

    public List<QualityIssueRecord> buildSoftwareIdentityUnknownLifecycleIssues(UUID tenantId, Set<UUID> suppressedIdentityIds) {
        String sql = """
                WITH exposure AS (
                    SELECT
                        ic.software_identity_id,
                        count(DISTINCT f.id) FILTER (WHERE f.status = 'OPEN') AS open_finding_count,
                        count(DISTINCT state.vulnerability_id) AS open_vulnerability_count
                    FROM inventory_components ic
                    LEFT JOIN findings f ON f.component_id = ic.id
                    LEFT JOIN component_vulnerability_states state ON state.component_id = ic.id
                    WHERE ic.component_status = 'ACTIVE'
                      AND ic.software_identity_id IS NOT NULL
                    GROUP BY ic.software_identity_id
                )
                SELECT
                    sis.software_identity_id,
                    sis.display_name,
                    sis.eol_slug,
                    sis.asset_count,
                    sis.component_count,
                    sis.unknown_eol_component_count,
                    sis.last_observed_at,
                    CASE
                        WHEN coalesce(array_length(sis.source_systems, 1), 0) = 1 THEN sis.source_systems[1]
                        WHEN coalesce(array_length(sis.source_systems, 1), 0) > 1 THEN 'multiple'
                        ELSE NULL
                    END AS source_system,
                    CASE
                        WHEN coalesce(array_length(sis.ecosystems, 1), 0) = 1 THEN sis.ecosystems[1]
                        WHEN coalesce(array_length(sis.ecosystems, 1), 0) > 1 THEN 'multiple'
                        ELSE NULL
                    END AS ecosystem,
                    coalesce(exposure.open_finding_count, 0) AS open_finding_count,
                    coalesce(exposure.open_vulnerability_count, 0) AS open_vulnerability_count
                FROM software_identity_summary sis
                LEFT JOIN exposure ON exposure.software_identity_id = sis.software_identity_id
                WHERE sis.needs_eol_mapping = false
                  AND sis.eol_slug IS NOT NULL
                  AND sis.unknown_eol_component_count = sis.component_count
                  AND sis.component_count > 0
                ORDER BY sis.last_observed_at DESC NULLS LAST, sis.display_name ASC
                """;
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : jdbcTemplate.queryForList(sql, support.tenantParams(tenantId))) {
            UUID identityId = support.uuidValue(row.get("software_identity_id"));
            if (suppressedIdentityIds.contains(identityId)) {
                continue;
            }
            long openFindingCount = support.longValue(row.get("open_finding_count"));
            long openVulnerabilityCount = support.longValue(row.get("open_vulnerability_count"));
            long assetCount = support.longValue(row.get("asset_count"));
            long componentCount = support.longValue(row.get("component_count"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("displayName", support.stringValue(row.get("display_name")));
            evidence.put("eolSlug", support.stringValue(row.get("eol_slug")));
            evidence.put("unknownEolComponentCount", support.longValue(row.get("unknown_eol_component_count")));
            issues.add(support.issue(
                    tenantId,
                    "EOL",
                    "software_identity_unknown_lifecycle",
                    "software-identity:" + support.stringValue(row.get("software_identity_id")) + ":unknown-lifecycle",
                    openFindingCount > 0 ? "HIGH" : "MEDIUM",
                    "mapped_slug_still_resolves_to_unknown_lifecycle",
                    "Software identity lifecycle is still unknown after mapping",
                    "SOFTWARE_IDENTITY",
                    support.stringValue(row.get("software_identity_id")),
                    support.stringValue(row.get("display_name")),
                    "Mapped slug: " + support.stringValue(row.get("eol_slug")),
                    null,
                    null,
                    identityId,
                    null,
                    null,
                    support.stringValue(row.get("source_system")),
                    support.stringValue(row.get("ecosystem")),
                    support.affectsActiveFindings(openFindingCount, openVulnerabilityCount),
                    assetCount,
                    componentCount,
                    openFindingCount,
                    openVulnerabilityCount,
                    support.instantValue(row.get("last_observed_at")),
                    support.instantValue(row.get("last_observed_at")),
                    evidence
            ));
        }
        return issues;
    }

    public List<QualityIssueRecord> buildSoftwareIdentityCycleUnresolvedIssues(UUID tenantId, Set<UUID> suppressedIdentityIds) {
        String sql = """
                WITH exposure AS (
                    SELECT
                        ic.software_identity_id,
                        count(DISTINCT f.id) FILTER (WHERE f.status = 'OPEN') AS open_finding_count,
                        count(DISTINCT state.vulnerability_id) AS open_vulnerability_count
                    FROM inventory_components ic
                    LEFT JOIN findings f ON f.component_id = ic.id
                    LEFT JOIN component_vulnerability_states state ON state.component_id = ic.id
                    WHERE ic.component_status = 'ACTIVE'
                      AND ic.software_identity_id IS NOT NULL
                    GROUP BY ic.software_identity_id
                )
                SELECT
                    sis.software_identity_id,
                    sis.display_name,
                    sis.eol_slug,
                    sis.asset_count,
                    sis.component_count,
                    sis.unknown_eol_component_count,
                    sis.last_observed_at,
                    CASE
                        WHEN coalesce(array_length(sis.source_systems, 1), 0) = 1 THEN sis.source_systems[1]
                        WHEN coalesce(array_length(sis.source_systems, 1), 0) > 1 THEN 'multiple'
                        ELSE NULL
                    END AS source_system,
                    CASE
                        WHEN coalesce(array_length(sis.ecosystems, 1), 0) = 1 THEN sis.ecosystems[1]
                        WHEN coalesce(array_length(sis.ecosystems, 1), 0) > 1 THEN 'multiple'
                        ELSE NULL
                    END AS ecosystem,
                    coalesce(exposure.open_finding_count, 0) AS open_finding_count,
                    coalesce(exposure.open_vulnerability_count, 0) AS open_vulnerability_count
                FROM software_identity_summary sis
                LEFT JOIN exposure ON exposure.software_identity_id = sis.software_identity_id
                WHERE sis.needs_eol_mapping = false
                  AND sis.eol_slug IS NOT NULL
                  AND sis.unknown_eol_component_count > 0
                  AND sis.unknown_eol_component_count < sis.component_count
                ORDER BY sis.last_observed_at DESC NULLS LAST, sis.display_name ASC
                """;
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : jdbcTemplate.queryForList(sql, support.tenantParams(tenantId))) {
            UUID identityId = support.uuidValue(row.get("software_identity_id"));
            if (suppressedIdentityIds.contains(identityId)) {
                continue;
            }
            long openFindingCount = support.longValue(row.get("open_finding_count"));
            long openVulnerabilityCount = support.longValue(row.get("open_vulnerability_count"));
            long assetCount = support.longValue(row.get("asset_count"));
            long componentCount = support.longValue(row.get("component_count"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("displayName", support.stringValue(row.get("display_name")));
            evidence.put("eolSlug", support.stringValue(row.get("eol_slug")));
            evidence.put("unknownEolComponentCount", support.longValue(row.get("unknown_eol_component_count")));
            issues.add(support.issue(
                    tenantId,
                    "EOL",
                    "software_identity_cycle_unresolved",
                    "software-identity:" + support.stringValue(row.get("software_identity_id")) + ":cycle-unresolved",
                    support.severityForExposureIssue(openFindingCount, openVulnerabilityCount, "MEDIUM"),
                    "mapped_slug_has_unresolved_version_cycles",
                    "Software identity has unresolved EOL cycles",
                    "SOFTWARE_IDENTITY",
                    support.stringValue(row.get("software_identity_id")),
                    support.stringValue(row.get("display_name")),
                    "Mapped slug: " + support.stringValue(row.get("eol_slug")),
                    null,
                    null,
                    identityId,
                    null,
                    null,
                    support.stringValue(row.get("source_system")),
                    support.stringValue(row.get("ecosystem")),
                    support.affectsActiveFindings(openFindingCount, openVulnerabilityCount),
                    assetCount,
                    componentCount,
                    openFindingCount,
                    openVulnerabilityCount,
                    support.instantValue(row.get("last_observed_at")),
                    support.instantValue(row.get("last_observed_at")),
                    evidence
            ));
        }
        return issues;
    }
}
