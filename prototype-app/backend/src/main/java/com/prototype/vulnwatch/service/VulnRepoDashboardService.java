package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.VulnRepoDashboardResponse;
import com.prototype.vulnwatch.dto.VulnRepoSoftwareAssetsResponse;
import java.sql.Timestamp;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class VulnRepoDashboardService {

    private static final List<String> SEVERITY_ORDER = List.of("CRITICAL", "HIGH", "MEDIUM", "LOW");
    private static final int LIST_LIMIT = 5;
    private static final int IMPACTED_ASSET_LIMIT = 9;

    private final SoftwareIdentitySummaryProjectionService softwareIdentitySummaryProjectionService;
    private final NamedParameterJdbcTemplate jdbcTemplate;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;

    public VulnRepoDashboardService(
            SoftwareIdentitySummaryProjectionService softwareIdentitySummaryProjectionService,
            NamedParameterJdbcTemplate jdbcTemplate,
            TenantSchemaExecutionService tenantSchemaExecutionService
    ) {
        this.softwareIdentitySummaryProjectionService = softwareIdentitySummaryProjectionService;
        this.jdbcTemplate = jdbcTemplate;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
    }

    public VulnRepoDashboardResponse get(Tenant tenant) {
        return tenantSchemaExecutionService.run(tenant, () -> {
            softwareIdentitySummaryProjectionService.ensureTenantProjection(tenant);
            UUID tenantId = tenant.getId();
            Instant now = Instant.now();
            SummarySnapshot summarySnapshot = loadSummarySnapshot(now.minus(7, ChronoUnit.DAYS));
            int exploitCoveragePercent = summarySnapshot.trackedCount() <= 0L
                    ? 0
                    : (int) Math.round((double) summarySnapshot.exploitCount() * 100.0d / (double) summarySnapshot.trackedCount());

            return new VulnRepoDashboardResponse(
                    now,
                    new VulnRepoDashboardResponse.SummaryCards(
                            summarySnapshot.trackedCount(),
                            summarySnapshot.trackedAddedLastWeek(),
                            summarySnapshot.applicableCount(),
                            summarySnapshot.applicableAddedLastWeek(),
                            summarySnapshot.impactedInvestigationDoneCount(),
                            summarySnapshot.impactedAddedLastWeek(),
                            summarySnapshot.remediationCveCount(),
                            summarySnapshot.needsAttentionCount(),
                            summarySnapshot.criticalCount(),
                            summarySnapshot.exploitCount(),
                            exploitCoveragePercent,
                            summarySnapshot.impactedCriticalCount(),
                            summarySnapshot.impactedHighCount(),
                            summarySnapshot.impactedMediumCount(),
                            summarySnapshot.impactedLowCount(),
                            summarySnapshot.impactedKevCount(),
                            summarySnapshot.kevAddedLastWeek(),
                            summarySnapshot.criticalUninvestigatedCount(),
                            summarySnapshot.kevReinvestigationCount()
                    ),
                    loadSeverityBreakdown(tenantId),
                    toResolutionStatus(summarySnapshot),
                    loadCriticalUnresolved(tenantId),
                    loadTopAffectedSoftware(tenantId),
                    loadRecentAdvisories(tenantId),
                    loadImpactedAssets(tenantId)
            );
        });
    }

    private record SummarySnapshot(
            long trackedCount,
            long trackedAddedLastWeek,
            long applicableCount,
            long applicableAddedLastWeek,
            long impactedInvestigationDoneCount,
            long impactedAddedLastWeek,
            long kevAddedLastWeek,
            long remediationCveCount,
            long needsAttentionCount,
            long criticalUninvestigatedCount,
            long kevReinvestigationCount,
            long criticalCount,
            long exploitCount,
            long impactedCriticalCount,
            long impactedHighCount,
            long impactedMediumCount,
            long impactedLowCount,
            long impactedKevCount,
            long unresolvedCount,
            long resolvedCount,
            long inProgressCount,
            long acceptedRiskCount
    ) {
        private static SummarySnapshot empty() {
            return new SummarySnapshot(
                    0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L,
                    0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L
            );
        }
    }

    public VulnRepoSoftwareAssetsResponse getSoftwareAssets(Tenant tenant, UUID softwareIdentityId) {
        return tenantSchemaExecutionService.run(tenant, () -> {
            softwareIdentitySummaryProjectionService.ensureTenantProjection(tenant);
            UUID tenantId = tenant.getId();
            MapSqlParameterSource params = new MapSqlParameterSource()
                    .addValue("tenantId", tenantId)
                    .addValue("softwareIdentityId", softwareIdentityId);

            VulnRepoSoftwareAssetsResponse header = jdbcTemplate.queryForObject(
                    """
                select
                  cast(sid.id as text) as software_identity_id,
                  sid.display_name,
                  coalesce(nullif(sid.vendor, ''), nullif(sid.product, ''), 'Unknown') as vendor,
                  count(distinct ic.asset_id) as impacted_asset_count
                from software_identities sid
                left join inventory_components ic
                  on ic.software_identity_id = sid.id
                 and ic.component_status = 'ACTIVE'
                left join component_vulnerability_states cvs
                  on cvs.component_id = ic.id
                left join org_cve_records o
                  on o.vulnerability_id = cvs.vulnerability_id
                 and upper(coalesce(o.impact_state, 'UNKNOWN')) not in ('FIXED', 'NOT_IMPACTED')
                where sid.id = :softwareIdentityId
                group by sid.id, sid.display_name, sid.vendor, sid.product
                """,
                    params,
                    (rs, rowNum) -> new VulnRepoSoftwareAssetsResponse(
                            rs.getString("software_identity_id"),
                            rs.getString("display_name"),
                            rs.getString("vendor"),
                            rs.getLong("impacted_asset_count"),
                            List.of()
                    )
            );

            List<VulnRepoSoftwareAssetsResponse.AssetItem> assets = jdbcTemplate.query(
                    """
                select
                  cast(a.id as text) as asset_id,
                  a.name as asset_name,
                  a.identifier as asset_identifier,
                  upper(cast(a.type as text)) as asset_type,
                  cast(ic.id as text) as component_id,
                  coalesce(nullif(ic.version, ''), nullif(ic.normalized_version, ''), '-') as version,
                  coalesce(nullif(lower(coalesce(u.ingestion_source_system, '')), ''), '-') as source_system,
                  count(distinct case
                    when upper(coalesce(o.impact_state, 'UNKNOWN')) not in ('FIXED', 'NOT_IMPACTED') then cvs.vulnerability_id
                  end) as open_cve_count,
                  count(distinct case
                    when f.status = 'OPEN' then f.id
                  end) as open_finding_count,
                  max(ic.last_observed_at) as last_observed_at
                from inventory_components ic
                join assets a on a.id = ic.asset_id
                left join sbom_uploads u on u.id = ic.sbom_upload_id
                left join component_vulnerability_states cvs
                  on cvs.component_id = ic.id
                left join org_cve_records o
                  on o.vulnerability_id = cvs.vulnerability_id
                left join findings f
                  on f.asset_id = ic.asset_id
                 and f.component_id = ic.id
                 and f.status = 'OPEN'
                where ic.software_identity_id = :softwareIdentityId
                  and ic.component_status = 'ACTIVE'
                group by a.id, a.name, a.identifier, a.type, ic.id, ic.version, ic.normalized_version, u.ingestion_source_system
                order by open_cve_count desc, open_finding_count desc, a.name asc, version asc
                """,
                    params,
                    (rs, rowNum) -> new VulnRepoSoftwareAssetsResponse.AssetItem(
                            rs.getString("asset_id"),
                            rs.getString("asset_name"),
                            rs.getString("asset_identifier"),
                            rs.getString("asset_type"),
                            rs.getString("component_id"),
                            rs.getString("version"),
                            rs.getString("source_system"),
                            rs.getLong("open_cve_count"),
                            rs.getLong("open_finding_count"),
                            getInstant(rs, "last_observed_at")
                    )
            );

            return new VulnRepoSoftwareAssetsResponse(
                    header.softwareIdentityId(),
                    header.displayName(),
                    header.vendor(),
                    assets.size(),
                    assets
            );
        });
    }

    private SummarySnapshot loadSummarySnapshot(Instant weekStart) {
        SummarySnapshot snapshot = jdbcTemplate.queryForObject(
                """
                with finding_presence as (
                  select distinct vulnerability_id
                  from findings
                ), suppressed_finding_counts as (
                  select count(distinct vulnerability_id) as accepted_risk_count
                  from findings
                  where status = 'SUPPRESSED'
                ), base as (
                  select
                    o.vulnerability_id,
                    o.created_at,
                    o.applicability_state,
                    upper(coalesce(o.impact_state, 'UNKNOWN')) as impact_state,
                    upper(coalesce(o.severity, 'UNKNOWN')) as severity,
                    coalesce(o.in_kev, false) as in_kev,
                    coalesce(o.epss_score, 0.0) as epss_score,
                    coalesce(o.matched_asset_count, 0) as matched_asset_count,
                    case when fp.vulnerability_id is not null then true else false end as has_finding
                  from org_cve_records o
                  left join finding_presence fp
                    on fp.vulnerability_id = o.vulnerability_id
                )
                select
                  count(*) as tracked_count,
                  count(*) filter (where created_at >= :weekStart) as tracked_added_last_week,
                  count(*) filter (where applicability_state = 'APPLICABLE') as applicable_count,
                  count(*) filter (where applicability_state = 'APPLICABLE' and created_at >= :weekStart) as applicable_added_last_week,
                  count(*) filter (where applicability_state = 'APPLICABLE' and matched_asset_count > 0) as impacted_investigation_done_count,
                  count(*) filter (where created_at >= :weekStart and impact_state in ('IMPACTED', 'NO_PATCH')) as impacted_added_last_week,
                  count(*) filter (where created_at >= :weekStart and in_kev = true) as kev_added_last_week,
                  count(*) filter (where has_finding) as remediation_cve_count,
                  count(*) filter (where impact_state in ('IMPACTED', 'NO_PATCH') and has_finding = false) as needs_attention_count,
                  count(*) filter (
                    where severity = 'CRITICAL'
                      and applicability_state = 'APPLICABLE'
                      and impact_state = 'UNKNOWN'
                      and has_finding = false
                  ) as critical_uninvestigated_count,
                  count(*) filter (
                    where in_kev = true
                      and applicability_state = 'APPLICABLE'
                      and matched_asset_count > 0
                      and impact_state not in ('FIXED', 'NOT_IMPACTED')
                      and has_finding = false
                  ) as kev_reinvestigation_count,
                  count(*) filter (where severity = 'CRITICAL') as critical_count,
                  count(*) filter (where in_kev = true or epss_score >= 0.9) as exploit_count,
                  count(*) filter (
                    where applicability_state = 'APPLICABLE'
                      and matched_asset_count > 0
                      and severity = 'CRITICAL'
                  ) as impacted_critical_count,
                  count(*) filter (
                    where applicability_state = 'APPLICABLE'
                      and matched_asset_count > 0
                      and severity = 'HIGH'
                  ) as impacted_high_count,
                  count(*) filter (
                    where applicability_state = 'APPLICABLE'
                      and matched_asset_count > 0
                      and severity = 'MEDIUM'
                  ) as impacted_medium_count,
                  count(*) filter (
                    where applicability_state = 'APPLICABLE'
                      and matched_asset_count > 0
                      and severity = 'LOW'
                  ) as impacted_low_count,
                  count(*) filter (
                    where applicability_state = 'APPLICABLE'
                      and matched_asset_count > 0
                      and in_kev = true
                  ) as impacted_kev_count,
                  count(*) filter (where impact_state in ('IMPACTED', 'NO_PATCH', 'UNKNOWN')) as unresolved_count,
                  count(*) filter (where impact_state in ('FIXED', 'NOT_IMPACTED')) as resolved_count,
                  count(*) filter (where impact_state = 'UNDER_INVESTIGATION') as in_progress_count,
                  coalesce((select accepted_risk_count from suppressed_finding_counts), 0) as accepted_risk_count
                from base
                """,
                new MapSqlParameterSource()
                        .addValue("weekStart", Timestamp.from(weekStart)),
                (rs, rowNum) -> new SummarySnapshot(
                        rs.getLong("tracked_count"),
                        rs.getLong("tracked_added_last_week"),
                        rs.getLong("applicable_count"),
                        rs.getLong("applicable_added_last_week"),
                        rs.getLong("impacted_investigation_done_count"),
                        rs.getLong("impacted_added_last_week"),
                        rs.getLong("kev_added_last_week"),
                        rs.getLong("remediation_cve_count"),
                        rs.getLong("needs_attention_count"),
                        rs.getLong("critical_uninvestigated_count"),
                        rs.getLong("kev_reinvestigation_count"),
                        rs.getLong("critical_count"),
                        rs.getLong("exploit_count"),
                        rs.getLong("impacted_critical_count"),
                        rs.getLong("impacted_high_count"),
                        rs.getLong("impacted_medium_count"),
                        rs.getLong("impacted_low_count"),
                        rs.getLong("impacted_kev_count"),
                        rs.getLong("unresolved_count"),
                        rs.getLong("resolved_count"),
                        rs.getLong("in_progress_count"),
                        rs.getLong("accepted_risk_count")
                )
        );
        return snapshot == null ? SummarySnapshot.empty() : snapshot;
    }

    private List<VulnRepoDashboardResponse.SeverityBreakdownItem> loadSeverityBreakdown(UUID tenantId) {
        Map<String, Long> counts = new LinkedHashMap<>();
        SEVERITY_ORDER.forEach((severity) -> counts.put(severity, 0L));
        counts.put("UNKNOWN", 0L);

        jdbcTemplate.query(
                """
                select upper(coalesce(o.severity, 'UNKNOWN')) as severity, count(*) as total
                from org_cve_records o
                group by upper(coalesce(o.severity, 'UNKNOWN'))
                """,
                new MapSqlParameterSource().addValue("tenantId", tenantId),
                rs -> {
                    counts.put(rs.getString("severity"), rs.getLong("total"));
                }
        );

        List<VulnRepoDashboardResponse.SeverityBreakdownItem> items = new ArrayList<>();
        counts.forEach((severity, total) -> {
            if (total > 0L || !"UNKNOWN".equals(severity)) {
                items.add(new VulnRepoDashboardResponse.SeverityBreakdownItem(severity, total));
            }
        });
        return items;
    }

    private VulnRepoDashboardResponse.ResolutionStatus toResolutionStatus(SummarySnapshot snapshot) {
        return new VulnRepoDashboardResponse.ResolutionStatus(
                snapshot.unresolvedCount(),
                snapshot.resolvedCount(),
                snapshot.inProgressCount(),
                snapshot.acceptedRiskCount()
        );
    }

    private List<VulnRepoDashboardResponse.CriticalUnresolvedItem> loadCriticalUnresolved(UUID tenantId) {
        return jdbcTemplate.query(
                """
                select
                  o.external_id,
                  coalesce(nullif(v.description_snippet, ''), nullif(v.title, ''), o.external_id) as title,
                  upper(coalesce(o.severity, 'UNKNOWN')) as severity,
                  upper(coalesce(o.impact_state, 'UNKNOWN')) as impact_state,
                  coalesce(o.impact_reason, '') as impact_reason,
                  o.in_kev,
                  count(f.id) as finding_count
                from org_cve_records o
                join vulnerabilities v on v.id = o.vulnerability_id
                left join findings f
                  on f.vulnerability_id = o.vulnerability_id
                 and f.status = 'OPEN'
                where upper(coalesce(o.impact_state, 'UNKNOWN')) not in ('FIXED', 'NOT_IMPACTED')
                group by o.external_id, v.description_snippet, v.title, o.severity, o.impact_state, o.impact_reason, o.in_kev, o.cvss_score
                having count(f.id) > 0
                order by
                  case upper(coalesce(o.severity, 'UNKNOWN'))
                    when 'CRITICAL' then 0
                    when 'HIGH' then 1
                    when 'MEDIUM' then 2
                    when 'LOW' then 3
                    else 4
                  end,
                  count(f.id) desc,
                  coalesce(o.cvss_score, 0) desc,
                  o.external_id asc
                limit :limit
                """,
                new MapSqlParameterSource()
                        .addValue("tenantId", tenantId)
                        .addValue("limit", LIST_LIMIT),
                (rs, rowNum) -> new VulnRepoDashboardResponse.CriticalUnresolvedItem(
                        rs.getString("external_id"),
                        rs.getString("title"),
                        rs.getString("severity"),
                        toStatusLabel(rs.getString("impact_reason"), rs.getString("impact_state")),
                        rs.getBoolean("in_kev"),
                        rs.getLong("finding_count")
                )
        );
    }

    private List<VulnRepoDashboardResponse.TopAffectedSoftwareItem> loadTopAffectedSoftware(UUID tenantId) {
        return jdbcTemplate.query(
                """
                with severity_rank as (
                  select
                    ic.software_identity_id as software_identity_id,
                    min(
                      case upper(coalesce(o.severity, 'UNKNOWN'))
                        when 'CRITICAL' then 0
                        when 'HIGH' then 1
                        when 'MEDIUM' then 2
                        when 'LOW' then 3
                        else 4
                      end
                    ) as min_rank
                  from component_vulnerability_states cvs
                  join inventory_components ic on ic.id = cvs.component_id
                  join org_cve_records o
                    on o.vulnerability_id = cvs.vulnerability_id
                  where ic.software_identity_id is not null
                  group by ic.software_identity_id
                ), severity_counts as (
                  select
                    ic.software_identity_id as software_identity_id,
                    count(distinct case when upper(coalesce(o.severity, 'UNKNOWN')) = 'CRITICAL' then cvs.vulnerability_id end) as critical_count,
                    count(distinct case when upper(coalesce(o.severity, 'UNKNOWN')) = 'HIGH' then cvs.vulnerability_id end) as high_count
                  from component_vulnerability_states cvs
                  join inventory_components ic on ic.id = cvs.component_id
                  join org_cve_records o
                    on o.vulnerability_id = cvs.vulnerability_id
                  where ic.software_identity_id is not null
                  group by ic.software_identity_id
                )
                select
                  cast(sid.id as text) as software_identity_id,
                  sid.display_name,
                  coalesce(nullif(sid.vendor, ''), nullif(sid.product, ''), 'Unknown') as vendor,
                  count(distinct cvs.vulnerability_id) as cve_count,
                  coalesce(sc.critical_count, 0) as critical_count,
                  coalesce(sc.high_count, 0) as high_count,
                  count(distinct ic.asset_id) as impacted_asset_count,
                  coalesce(sr.min_rank, 4) as min_rank
                from inventory_components ic
                join software_identities sid on sid.id = ic.software_identity_id
                join component_vulnerability_states cvs
                  on cvs.component_id = ic.id
                join org_cve_records o
                  on o.vulnerability_id = cvs.vulnerability_id
                left join severity_rank sr on sr.software_identity_id = sid.id
                left join severity_counts sc on sc.software_identity_id = sid.id
                where ic.component_status = 'ACTIVE'
                group by sid.id, sid.display_name, sid.vendor, sid.product, sr.min_rank, sc.critical_count, sc.high_count
                having count(distinct cvs.vulnerability_id) > 0
                order by coalesce(sc.critical_count, 0) desc,
                         coalesce(sc.high_count, 0) desc,
                         count(distinct cvs.vulnerability_id) desc,
                         sid.display_name asc
                limit :limit
                """,
                new MapSqlParameterSource()
                        .addValue("tenantId", tenantId)
                        .addValue("limit", LIST_LIMIT),
                (rs, rowNum) -> new VulnRepoDashboardResponse.TopAffectedSoftwareItem(
                        rs.getString("software_identity_id"),
                        rs.getString("display_name"),
                        rs.getString("vendor"),
                        rs.getLong("cve_count"),
                        rs.getLong("critical_count"),
                        rs.getLong("high_count"),
                        rs.getLong("impacted_asset_count"),
                        rankToSeverity(rs.getInt("min_rank"))
                )
        );
    }

    private List<VulnRepoDashboardResponse.RecentAdvisoryItem> loadRecentAdvisories(UUID tenantId) {
        return jdbcTemplate.query(
                """
                select
                  o.external_id,
                  coalesce(nullif(v.title, ''), nullif(v.description_snippet, ''), o.external_id) as title,
                  coalesce(nullif(v.description_snippet, ''), nullif(v.title, ''), o.external_id) as description_snippet,
                  upper(coalesce(o.severity, 'UNKNOWN')) as severity,
                  upper(cast(v.source as text)) as source,
                  v.published_at,
                  v.last_modified_at
                from org_cve_records o
                join vulnerabilities v on v.id = o.vulnerability_id
                order by coalesce(v.last_modified_at, v.published_at, o.updated_at, o.last_evaluated_at) desc, o.external_id asc
                limit :limit
                """,
                new MapSqlParameterSource()
                        .addValue("tenantId", tenantId)
                        .addValue("limit", LIST_LIMIT),
                (rs, rowNum) -> new VulnRepoDashboardResponse.RecentAdvisoryItem(
                        rs.getString("external_id"),
                        rs.getString("title"),
                        rs.getString("description_snippet"),
                        rs.getString("severity"),
                        rs.getString("source"),
                        getInstant(rs, "published_at"),
                        getInstant(rs, "last_modified_at")
                )
        );
    }

    private List<VulnRepoDashboardResponse.ImpactedAssetItem> loadImpactedAssets(UUID tenantId) {
        return jdbcTemplate.query(
                """
                select
                  cast(a.id as text) as asset_id,
                  a.name as asset_name,
                  upper(cast(a.type as text)) as asset_type,
                  a.identifier,
                  a.environment,
                  count(distinct cvs.vulnerability_id) as cve_count
                from component_vulnerability_states cvs
                join inventory_components ic on ic.id = cvs.component_id
                join assets a on a.id = ic.asset_id
                join org_cve_records o
                  on o.vulnerability_id = cvs.vulnerability_id
                where upper(coalesce(o.impact_state, 'UNKNOWN')) not in ('FIXED', 'NOT_IMPACTED')
                group by a.id, a.name, a.type, a.identifier, a.environment
                order by count(distinct cvs.vulnerability_id) desc, a.name asc
                limit :limit
                """,
                new MapSqlParameterSource()
                        .addValue("tenantId", tenantId)
                        .addValue("limit", IMPACTED_ASSET_LIMIT),
                (rs, rowNum) -> new VulnRepoDashboardResponse.ImpactedAssetItem(
                        rs.getString("asset_id"),
                        rs.getString("asset_name"),
                        rs.getString("asset_type"),
                        rs.getString("identifier"),
                        rs.getString("environment"),
                        rs.getLong("cve_count")
                )
        );
    }

    private String toStatusLabel(String impactReason, String impactState) {
        if (impactReason != null && !impactReason.isBlank()) {
            return titleCase(impactReason.replace('_', ' '));
        }
        if (impactState == null || impactState.isBlank()) {
            return "Unknown";
        }
        return titleCase(impactState.replace('_', ' '));
    }

    private String rankToSeverity(int rank) {
        return switch (rank) {
            case 0 -> "CRITICAL";
            case 1 -> "HIGH";
            case 2 -> "MEDIUM";
            case 3 -> "LOW";
            default -> "UNKNOWN";
        };
    }

    private String titleCase(String value) {
        String[] tokens = value.toLowerCase(Locale.ROOT).split("\\s+");
        StringBuilder builder = new StringBuilder();
        for (String token : tokens) {
            if (token.isBlank()) {
                continue;
            }
            if (builder.length() > 0) {
                builder.append(' ');
            }
            builder.append(Character.toUpperCase(token.charAt(0)));
            if (token.length() > 1) {
                builder.append(token.substring(1));
            }
        }
        return builder.toString();
    }

    private Instant getInstant(ResultSet rs, String column) throws SQLException {
        return rs.getTimestamp(column) == null ? null : rs.getTimestamp(column).toInstant();
    }
}
