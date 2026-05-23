package com.prototype.vulnwatch.service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class ProjectionFreshnessIssueBuilder {

    private final NamedParameterJdbcTemplate jdbcTemplate;
    private final QualityIssueJdbcSupport support;

    public ProjectionFreshnessIssueBuilder(
            NamedParameterJdbcTemplate jdbcTemplate,
            QualityIssueJdbcSupport support
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.support = support;
    }

    public List<QualityIssueRecord> buildSummaryProjectionStaleIssues(UUID tenantId) {
        List<QualityIssueRecord> issues = new ArrayList<>();
        MapSqlParameterSource params = support.tenantParams(tenantId);

        long activeIdentityComponents = support.queryLong("""
                SELECT COUNT(*)
                FROM inventory_components
                WHERE component_status = 'ACTIVE'
                  AND software_identity_id IS NOT NULL
                """, params);
        long identitySummaryRows = support.queryLong("""
                SELECT COUNT(*)
                FROM software_identity_summary
                """, params);
        if (activeIdentityComponents > 0 && identitySummaryRows == 0) {
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("activeIdentityComponents", activeIdentityComponents);
            evidence.put("summaryRows", identitySummaryRows);
            issues.add(support.issue(
                    tenantId,
                    "PROJECTION_FRESHNESS",
                    "summary_projection_stale",
                    "projection:software-identity-summary:stale",
                    "HIGH",
                    "software_identity_summary_missing",
                    "Software identity summary projection is stale or missing",
                    "READ_MODEL",
                    "software-identity-summary",
                    "Software Identities",
                    "Summary rows are missing for active inventory",
                    null,
                    null,
                    null,
                    null,
                    null,
                    "projection",
                    null,
                    false,
                    0,
                    activeIdentityComponents,
                    0,
                    0,
                    Instant.now(),
                    Instant.now(),
                    evidence
            ));
        }

        long vulnerabilityCount = support.queryLong("SELECT COUNT(*) FROM vulnerabilities", new MapSqlParameterSource());
        long vulnerabilitySummaryCount = support.queryLong("SELECT COUNT(*) FROM vulnerability_intel_summary", new MapSqlParameterSource());
        if (vulnerabilityCount > 0 && vulnerabilitySummaryCount == 0) {
            long openFindingCount = support.queryLong("""
                    SELECT COUNT(*)
                    FROM findings
                    WHERE status = 'OPEN'
                    """, params);
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("vulnerabilityCount", vulnerabilityCount);
            evidence.put("summaryRows", vulnerabilitySummaryCount);
            issues.add(support.issue(
                    tenantId,
                    "PROJECTION_FRESHNESS",
                    "summary_projection_stale",
                    "projection:vulnerability-intel-summary:stale",
                    openFindingCount > 0 ? "HIGH" : "MEDIUM",
                    "vulnerability_intel_summary_missing",
                    "Vulnerability repository summary projection is stale or missing",
                    "READ_MODEL",
                    "vulnerability-intel-summary",
                    "Vulnerability Repository",
                    "Summary rows are missing for tracked vulnerabilities",
                    null,
                    null,
                    null,
                    null,
                    null,
                    "projection",
                    null,
                    openFindingCount > 0,
                    0,
                    0,
                    openFindingCount,
                    0,
                    Instant.now(),
                    Instant.now(),
                    evidence
            ));
        }
        return issues;
    }

    public List<QualityIssueRecord> buildCrossViewCountMismatchIssues(UUID tenantId) {
        List<QualityIssueRecord> issues = new ArrayList<>();
        MapSqlParameterSource params = support.tenantParams(tenantId);

        long activeIdentityComponents = support.queryLong("""
                SELECT COUNT(*)
                FROM inventory_components
                WHERE component_status = 'ACTIVE'
                  AND software_identity_id IS NOT NULL
                """, params);
        long projectedIdentityComponents = support.queryLong("""
                SELECT COALESCE(SUM(component_count), 0)
                FROM software_identity_summary
                """, params);
        if (activeIdentityComponents > 0
                && projectedIdentityComponents > 0
                && activeIdentityComponents != projectedIdentityComponents) {
            long openFindingCount = support.queryLong("""
                    SELECT COUNT(*)
                    FROM findings
                    WHERE status = 'OPEN'
                    """, params);
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("activeIdentityComponents", activeIdentityComponents);
            evidence.put("projectedIdentityComponents", projectedIdentityComponents);
            issues.add(support.issue(
                    tenantId,
                    "PROJECTION_FRESHNESS",
                    "cross_view_count_mismatch",
                    "projection:software-identity-summary:mismatch",
                    openFindingCount > 0 ? "CRITICAL" : "HIGH",
                    "software_identity_summary_component_count_mismatch",
                    "Software identity summary count disagrees with active inventory",
                    "READ_MODEL",
                    "software-identity-summary",
                    "Software Identities",
                    activeIdentityComponents + " inventory components vs " + projectedIdentityComponents + " projected",
                    null,
                    null,
                    null,
                    null,
                    null,
                    "projection",
                    null,
                    openFindingCount > 0,
                    0,
                    activeIdentityComponents,
                    openFindingCount,
                    0,
                    Instant.now(),
                    Instant.now(),
                    evidence
            ));
        }

        long vulnerabilityCount = support.queryLong("SELECT COUNT(*) FROM vulnerabilities", new MapSqlParameterSource());
        long vulnerabilitySummaryCount = support.queryLong("SELECT COUNT(*) FROM vulnerability_intel_summary", new MapSqlParameterSource());
        if (vulnerabilitySummaryCount > 0 && vulnerabilityCount != vulnerabilitySummaryCount) {
            long openFindingCount = support.queryLong("""
                    SELECT COUNT(*)
                    FROM findings
                    WHERE status = 'OPEN'
                    """, params);
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("vulnerabilityCount", vulnerabilityCount);
            evidence.put("summaryRows", vulnerabilitySummaryCount);
            issues.add(support.issue(
                    tenantId,
                    "PROJECTION_FRESHNESS",
                    "cross_view_count_mismatch",
                    "projection:vulnerability-intel-summary:mismatch",
                    openFindingCount > 0 ? "CRITICAL" : "HIGH",
                    "vulnerability_intel_summary_count_mismatch",
                    "Vulnerability repository summary count disagrees with tracked vulnerabilities",
                    "READ_MODEL",
                    "vulnerability-intel-summary",
                    "Vulnerability Repository",
                    vulnerabilityCount + " vulnerabilities vs " + vulnerabilitySummaryCount + " projected summaries",
                    null,
                    null,
                    null,
                    null,
                    null,
                    "projection",
                    null,
                    openFindingCount > 0,
                    0,
                    0,
                    openFindingCount,
                    0,
                    Instant.now(),
                    Instant.now(),
                    evidence
            ));
        }
        return issues;
    }

    public List<QualityIssueRecord> buildPostRecomputeProjectionPendingIssues(UUID tenantId) {
        String sql = """
                SELECT
                    r.id,
                    r.sync_type,
                    r.status,
                    r.started_at,
                    r.records_fetched,
                    r.records_inserted,
                    r.records_updated
                FROM sync_runs r
                WHERE lower(r.status) IN ('queued', 'running')
                  AND (
                    lower(r.sync_type) LIKE '%recompute%'
                    OR lower(r.sync_type) LIKE '%backfill%'
                    OR lower(r.sync_type) LIKE '%repair%'
                    OR lower(r.sync_type) LIKE '%denormalize%'
                    OR lower(r.sync_type) LIKE '%mapping%'
                  )
                ORDER BY r.started_at DESC
                """;
        List<QualityIssueRecord> issues = new ArrayList<>();
        for (Map<String, Object> row : jdbcTemplate.queryForList(sql, new MapSqlParameterSource())) {
            String syncType = support.stringValue(row.get("sync_type"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("syncType", syncType);
            evidence.put("status", support.stringValue(row.get("status")));
            evidence.put("recordsFetched", support.longValue(row.get("records_fetched")));
            evidence.put("recordsInserted", support.longValue(row.get("records_inserted")));
            evidence.put("recordsUpdated", support.longValue(row.get("records_updated")));
            issues.add(support.issue(
                    tenantId,
                    "PROJECTION_FRESHNESS",
                    "post_recompute_projection_pending",
                    "sync-pending:" + support.stringValue(row.get("id")),
                    "LOW",
                    "projection_refresh_pending_after_recompute",
                    "Recompute-related job is still in progress",
                    "SYNC_RUN",
                    support.stringValue(row.get("id")),
                    syncType,
                    "Projection updates may still be settling",
                    null,
                    null,
                    support.uuidValue(row.get("id")),
                    null,
                    support.normalizeSource(syncType),
                    null,
                    false,
                    0,
                    0,
                    0,
                    0,
                    support.instantValue(row.get("started_at")),
                    support.instantValue(row.get("started_at")),
                    evidence
            ));
        }
        return issues;
    }
}
