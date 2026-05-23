package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.VulnRepoDashboardResponse;
import com.prototype.vulnwatch.dto.VulnRepoSoftwareAssetsResponse;
import java.sql.Timestamp;
import com.prototype.vulnwatch.repo.OrgCveRecordRepository;
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
    private static final List<String> RESOLVED_STATES = List.of("FIXED", "NOT_IMPACTED");
    private static final List<String> UNRESOLVED_STATES = List.of("IMPACTED", "NO_PATCH", "UNKNOWN");
    private static final List<String> IMPACTED_STATES = List.of("IMPACTED", "NO_PATCH");
    private static final int LIST_LIMIT = 5;
    private static final int IMPACTED_ASSET_LIMIT = 9;

    private final OrgCveRecordRepository orgCveRecordRepository;
    private final SoftwareIdentitySummaryProjectionService softwareIdentitySummaryProjectionService;
    private final NamedParameterJdbcTemplate jdbcTemplate;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;

    public VulnRepoDashboardService(
            OrgCveRecordRepository orgCveRecordRepository,
            SoftwareIdentitySummaryProjectionService softwareIdentitySummaryProjectionService,
            NamedParameterJdbcTemplate jdbcTemplate,
            TenantSchemaExecutionService tenantSchemaExecutionService
    ) {
        this.orgCveRecordRepository = orgCveRecordRepository;
        this.softwareIdentitySummaryProjectionService = softwareIdentitySummaryProjectionService;
        this.jdbcTemplate = jdbcTemplate;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
    }

    public VulnRepoDashboardResponse get(Tenant tenant) {
        return tenantSchemaExecutionService.run(tenant, () -> {
            softwareIdentitySummaryProjectionService.ensureTenantProjection(tenant);
            UUID tenantId = tenant.getId();
            Instant now = Instant.now();

            long trackedCount = orgCveRecordRepository.count();
            long trackedAddedLastWeek = countTrackedAddedLastWeek(tenantId, now.minus(7, ChronoUnit.DAYS));
            long applicableCount = countApplicableCves(tenantId, null);
            long applicableAddedLastWeek = countApplicableCves(tenantId, now.minus(7, ChronoUnit.DAYS));
            long impactedInvestigationDoneCount = countApplicableWithMatchedAssets(tenantId);
            long impactedAddedLastWeek = countImpactedAddedSince(tenantId, now.minus(7, ChronoUnit.DAYS));
            long kevAddedLastWeek = countKevAddedSince(tenantId, now.minus(7, ChronoUnit.DAYS));
            long remediationCveCount = countCvesWithFindings(tenantId);
            long needsAttentionCount = countNeedsAttention(tenantId);
            long criticalUninvestigatedCount = countCriticalUninvestigated(tenantId);
            long kevReinvestigationCount = countKevReinvestigation(tenantId);
            long criticalCount = countBySeverity(tenantId, "CRITICAL");
            long exploitCount = countExploitAvailable(tenantId);
            int exploitCoveragePercent = trackedCount <= 0L
                    ? 0
                    : (int) Math.round((double) exploitCount * 100.0d / (double) trackedCount);
            ImpactedBreakdown impactedBreakdown = loadImpactedBreakdown(tenantId);

            return new VulnRepoDashboardResponse(
                    now,
                    new VulnRepoDashboardResponse.SummaryCards(
                            trackedCount,
                            trackedAddedLastWeek,
                            applicableCount,
                            applicableAddedLastWeek,
                            impactedInvestigationDoneCount,
                            impactedAddedLastWeek,
                            remediationCveCount,
                            needsAttentionCount,
                            criticalCount,
                            exploitCount,
                            exploitCoveragePercent,
                            impactedBreakdown.critical(),
                            impactedBreakdown.high(),
                            impactedBreakdown.medium(),
                            impactedBreakdown.low(),
                            impactedBreakdown.kev(),
                            kevAddedLastWeek,
                            criticalUninvestigatedCount,
                            kevReinvestigationCount
                    ),
                    loadSeverityBreakdown(tenantId),
                    loadResolutionStatus(tenantId),
                    loadCriticalUnresolved(tenantId),
                    loadTopAffectedSoftware(tenantId),
                    loadRecentAdvisories(tenantId),
                    loadImpactedAssets(tenantId)
            );
        });
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

    private long countTrackedAddedLastWeek(UUID tenantId, Instant start) {
        Long count = jdbcTemplate.queryForObject(
                """
                select count(*)
                from org_cve_records o
                where o.created_at >= :start
                """,
                new MapSqlParameterSource()
                        .addValue("tenantId", tenantId)
                        .addValue("start", Timestamp.from(start)),
                Long.class
        );
        return count == null ? 0L : count;
    }

    private long countApplicableCves(UUID tenantId, Instant createdSince) {
        MapSqlParameterSource params = new MapSqlParameterSource().addValue("tenantId", tenantId);
        String createdSinceFilter = "";
        if (createdSince != null) {
            createdSinceFilter = " and o.created_at >= :createdSince";
            params.addValue("createdSince", Timestamp.from(createdSince));
        }
        Long count = jdbcTemplate.queryForObject(
                ("""
                select count(distinct o.vulnerability_id)
                from org_cve_records o
                where o.applicability_state = 'APPLICABLE'
                """ + createdSinceFilter),
                params,
                Long.class
        );
        return count == null ? 0L : count;
    }

    private record ImpactedBreakdown(long critical, long high, long medium, long low, long kev) {}

    private ImpactedBreakdown loadImpactedBreakdown(UUID tenantId) {
        ImpactedBreakdown result = jdbcTemplate.queryForObject(
                """
                select
                  count(case when upper(coalesce(o.severity, 'UNKNOWN')) = 'CRITICAL' then 1 end) as critical_count,
                  count(case when upper(coalesce(o.severity, 'UNKNOWN')) = 'HIGH' then 1 end) as high_count,
                  count(case when upper(coalesce(o.severity, 'UNKNOWN')) = 'MEDIUM' then 1 end) as medium_count,
                  count(case when upper(coalesce(o.severity, 'UNKNOWN')) = 'LOW' then 1 end) as low_count,
                  count(case when o.in_kev = true then 1 end) as kev_count
                from (
                  select distinct o.vulnerability_id, o.severity, o.in_kev
                  from org_cve_records o
                  where o.applicability_state = 'APPLICABLE'
                    and o.matched_asset_count > 0
                ) o
                """,
                new MapSqlParameterSource().addValue("tenantId", tenantId),
                (rs, rowNum) -> new ImpactedBreakdown(
                        rs.getLong("critical_count"),
                        rs.getLong("high_count"),
                        rs.getLong("medium_count"),
                        rs.getLong("low_count"),
                        rs.getLong("kev_count")
                )
        );
        return result != null ? result : new ImpactedBreakdown(0L, 0L, 0L, 0L, 0L);
    }

    private long countApplicableWithMatchedAssets(UUID tenantId) {
        Long count = jdbcTemplate.queryForObject(
                """
                select count(distinct o.vulnerability_id)
                from org_cve_records o
                where o.applicability_state = 'APPLICABLE'
                  and o.matched_asset_count > 0
                """,
                new MapSqlParameterSource().addValue("tenantId", tenantId),
                Long.class
        );
        return count == null ? 0L : count;
    }

    private long countImpactedAddedSince(UUID tenantId, Instant start) {
        Long count = jdbcTemplate.queryForObject(
                """
                select count(distinct o.vulnerability_id)
                from org_cve_records o
                where o.created_at >= :start
                  and upper(coalesce(o.impact_state, 'UNKNOWN')) in (:states)
                """,
                new MapSqlParameterSource()
                        .addValue("tenantId", tenantId)
                        .addValue("start", Timestamp.from(start))
                        .addValue("states", IMPACTED_STATES),
                Long.class
        );
        return count == null ? 0L : count;
    }

    private long countKevAddedSince(UUID tenantId, Instant start) {
        Long count = jdbcTemplate.queryForObject(
                """
                select count(distinct o.vulnerability_id)
                from org_cve_records o
                where o.created_at >= :start
                  and o.in_kev = true
                """,
                new MapSqlParameterSource()
                        .addValue("tenantId", tenantId)
                        .addValue("start", Timestamp.from(start)),
                Long.class
        );
        return count == null ? 0L : count;
    }

    private long countCvesWithFindings(UUID tenantId) {
        Long count = jdbcTemplate.queryForObject(
                """
                select count(distinct f.vulnerability_id)
                from findings f
                join org_cve_records o
                  on o.vulnerability_id = f.vulnerability_id
                """,
                new MapSqlParameterSource().addValue("tenantId", tenantId),
                Long.class
        );
        return count == null ? 0L : count;
    }

    private long countNeedsAttention(UUID tenantId) {
        Long count = jdbcTemplate.queryForObject(
                """
                select count(distinct o.vulnerability_id)
                from org_cve_records o
                where upper(coalesce(o.impact_state, 'UNKNOWN')) in (:states)
                  and not exists (
                    select 1
                    from findings f
                    where f.vulnerability_id = o.vulnerability_id
                  )
                """,
                new MapSqlParameterSource()
                        .addValue("tenantId", tenantId)
                        .addValue("states", IMPACTED_STATES),
                Long.class
        );
        return count == null ? 0L : count;
    }

    private long countCriticalUninvestigated(UUID tenantId) {
        Long count = jdbcTemplate.queryForObject(
                """
                select count(distinct o.vulnerability_id)
                from org_cve_records o
                where upper(coalesce(o.severity, 'UNKNOWN')) = 'CRITICAL'
                  and o.applicability_state = 'APPLICABLE'
                  and upper(coalesce(o.impact_state, 'UNKNOWN')) = 'UNKNOWN'
                  and not exists (
                    select 1
                    from findings f
                    where f.vulnerability_id = o.vulnerability_id
                  )
                """,
                new MapSqlParameterSource().addValue("tenantId", tenantId),
                Long.class
        );
        return count == null ? 0L : count;
    }

    private long countKevReinvestigation(UUID tenantId) {
        Long count = jdbcTemplate.queryForObject(
                """
                select count(distinct o.vulnerability_id)
                from org_cve_records o
                where o.in_kev = true
                  and o.applicability_state = 'APPLICABLE'
                  and o.matched_asset_count > 0
                  and upper(coalesce(o.impact_state, 'UNKNOWN')) not in ('FIXED', 'NOT_IMPACTED')
                  and not exists (
                    select 1
                    from findings f
                    where f.vulnerability_id = o.vulnerability_id
                  )
                """,
                new MapSqlParameterSource().addValue("tenantId", tenantId),
                Long.class
        );
        return count == null ? 0L : count;
    }

    private long countBySeverity(UUID tenantId, String severity) {
        Long count = jdbcTemplate.queryForObject(
                """
                select count(*)
                from org_cve_records o
                where upper(coalesce(o.severity, 'UNKNOWN')) = :severity
                """,
                new MapSqlParameterSource()
                        .addValue("tenantId", tenantId)
                        .addValue("severity", severity),
                Long.class
        );
        return count == null ? 0L : count;
    }

    private long countExploitAvailable(UUID tenantId) {
        Long count = jdbcTemplate.queryForObject(
                """
                select count(*)
                from org_cve_records o
                where (o.in_kev = true or coalesce(o.epss_score, 0) >= 0.9)
                """,
                new MapSqlParameterSource().addValue("tenantId", tenantId),
                Long.class
        );
        return count == null ? 0L : count;
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

    private VulnRepoDashboardResponse.ResolutionStatus loadResolutionStatus(UUID tenantId) {
        long unresolvedCount = countByImpactStates(tenantId, UNRESOLVED_STATES);
        long resolvedCount = countByImpactStates(tenantId, RESOLVED_STATES);
        long inProgressCount = countByImpactStates(tenantId, List.of("UNDER_INVESTIGATION"));
        Long acceptedRiskCount = jdbcTemplate.queryForObject(
                """
                select count(distinct f.vulnerability_id)
                from findings f
                where f.status = 'SUPPRESSED'
                """,
                new MapSqlParameterSource().addValue("tenantId", tenantId),
                Long.class
        );

        return new VulnRepoDashboardResponse.ResolutionStatus(
                unresolvedCount,
                resolvedCount,
                inProgressCount,
                acceptedRiskCount == null ? 0L : acceptedRiskCount
        );
    }

    private long countByImpactStates(UUID tenantId, List<String> states) {
        Long count = jdbcTemplate.queryForObject(
                """
                select count(distinct o.vulnerability_id)
                from org_cve_records o
                where upper(coalesce(o.impact_state, 'UNKNOWN')) in (:states)
                """,
                new MapSqlParameterSource()
                        .addValue("tenantId", tenantId)
                        .addValue("states", states),
                Long.class
        );
        return count == null ? 0L : count;
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
