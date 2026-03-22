package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.ApplicabilityState;
import com.prototype.vulnwatch.domain.OrgCveRecord;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.query.Param;

public interface OrgCveRecordRepository extends JpaRepository<OrgCveRecord, UUID> {
    interface ExposureSummaryRow {
        long getReviewQueueCount();
        Long getApplicableCount();
        Long getImpactedCount();
        Long getUnderInvestigationCount();
        Long getResolvedCount();
    }

    Optional<OrgCveRecord> findByTenantAndVulnerability_Id(Tenant tenant, UUID vulnerabilityId);

    List<OrgCveRecord> findByTenantAndVulnerability_IdIn(Tenant tenant, Collection<UUID> vulnerabilityIds);

    @Query("""
            select distinct o.tenant.id
            from OrgCveRecord o
            where o.vulnerability.id in :vulnerabilityIds
            """)
    Set<UUID> findDistinctTenantIdsByVulnerabilityIds(@Param("vulnerabilityIds") Collection<UUID> vulnerabilityIds);

    @Query("""
            select max(o.lastEvaluatedAt)
            from OrgCveRecord o
            where o.tenant = :tenant
            """)
    java.time.Instant findLatestLastEvaluatedAt(@Param("tenant") Tenant tenant);

    long countByTenant(Tenant tenant);

    long countByTenantAndApplicabilityState(Tenant tenant, ApplicabilityState applicabilityState);

    long countByTenantAndImpactedTrue(Tenant tenant);

    @Query("select o from OrgCveRecord o where o.tenant.id = :tenantId and o.vulnerability = :vulnerability")
    Optional<OrgCveRecord> findByTenantIdAndVulnerability(@Param("tenantId") UUID tenantId,
                                                           @Param("vulnerability") Vulnerability vulnerability);

    @EntityGraph(attributePaths = {"vulnerability"})
    @Query(
            value = """
                    select o
                    from OrgCveRecord o
                    where o.tenant = :tenant
                      and (:inKev is null or o.inKev = :inKev)
                      and (
                        o.impacted = true
                        or o.impactState = com.prototype.vulnwatch.domain.ImpactState.UNKNOWN
                        or o.impactState = com.prototype.vulnwatch.domain.ImpactState.UNDER_INVESTIGATION
                      )
                    order by
                      case when o.impacted = true then 1 else 0 end desc,
                      case when o.impactState = com.prototype.vulnwatch.domain.ImpactState.UNDER_INVESTIGATION then 1 else 0 end desc,
                      case when o.inKev = true then 1 else 0 end desc,
                      coalesce(o.epssScore, 0.0) desc,
                      coalesce(o.cvssScore, 0.0) desc,
                      o.externalId asc
                    """,
            countQuery = """
                    select count(o.id)
                    from OrgCveRecord o
                    where o.tenant = :tenant
                      and (:inKev is null or o.inKev = :inKev)
                      and (
                        o.impacted = true
                        or o.impactState = com.prototype.vulnwatch.domain.ImpactState.UNKNOWN
                        or o.impactState = com.prototype.vulnwatch.domain.ImpactState.UNDER_INVESTIGATION
                      )
                    """
    )
    Page<OrgCveRecord> findExposurePage(@Param("tenant") Tenant tenant, @Param("inKev") Boolean inKev, Pageable pageable);

    @EntityGraph(attributePaths = {"vulnerability"})
    @Query(
            value = """
                    select o
                    from OrgCveRecord o
                    where o.tenant = :tenant
                      and (:inKev is null or o.inKev = :inKev)
                      and (
                        o.impacted = true
                        or o.impactState = com.prototype.vulnwatch.domain.ImpactState.UNKNOWN
                        or o.impactState = com.prototype.vulnwatch.domain.ImpactState.UNDER_INVESTIGATION
                      )
                      and o.externalId = :externalId
                    order by
                      case when o.impacted = true then 1 else 0 end desc,
                      case when o.impactState = com.prototype.vulnwatch.domain.ImpactState.UNDER_INVESTIGATION then 1 else 0 end desc,
                      case when o.inKev = true then 1 else 0 end desc,
                      coalesce(o.epssScore, 0.0) desc,
                      coalesce(o.cvssScore, 0.0) desc,
                      o.externalId asc
                    """,
            countQuery = """
                    select count(o.id)
                    from OrgCveRecord o
                    where o.tenant = :tenant
                      and (:inKev is null or o.inKev = :inKev)
                      and (
                        o.impacted = true
                        or o.impactState = com.prototype.vulnwatch.domain.ImpactState.UNKNOWN
                        or o.impactState = com.prototype.vulnwatch.domain.ImpactState.UNDER_INVESTIGATION
                      )
                      and o.externalId = :externalId
                    """
    )
    Page<OrgCveRecord> findExposurePageByExternalId(
            @Param("tenant") Tenant tenant,
            @Param("externalId") String externalId,
            @Param("inKev") Boolean inKev,
            Pageable pageable
    );

    @EntityGraph(attributePaths = {"vulnerability"})
    @Query(
            value = """
                    select o
                    from OrgCveRecord o
                    join o.vulnerability v
                    where o.tenant = :tenant
                      and (:inKev is null or o.inKev = :inKev)
                      and (
                        o.impacted = true
                        or o.impactState = com.prototype.vulnwatch.domain.ImpactState.UNKNOWN
                        or o.impactState = com.prototype.vulnwatch.domain.ImpactState.UNDER_INVESTIGATION
                      )
                      and (
                        upper(o.externalId) like concat('%', :queryUpper, '%')
                        or upper(o.severity) like concat('%', :queryUpper, '%')
                        or upper(coalesce(v.title, '')) like concat('%', :queryUpper, '%')
                        or upper(coalesce(v.descriptionSnippet, '')) like concat('%', :queryUpper, '%')
                      )
                    order by
                      case when o.impacted = true then 1 else 0 end desc,
                      case when o.impactState = com.prototype.vulnwatch.domain.ImpactState.UNDER_INVESTIGATION then 1 else 0 end desc,
                      case when o.inKev = true then 1 else 0 end desc,
                      coalesce(o.epssScore, 0.0) desc,
                      coalesce(o.cvssScore, 0.0) desc,
                      o.externalId asc
                    """,
            countQuery = """
                    select count(o.id)
                    from OrgCveRecord o
                    join o.vulnerability v
                    where o.tenant = :tenant
                      and (:inKev is null or o.inKev = :inKev)
                      and (
                        o.impacted = true
                        or o.impactState = com.prototype.vulnwatch.domain.ImpactState.UNKNOWN
                        or o.impactState = com.prototype.vulnwatch.domain.ImpactState.UNDER_INVESTIGATION
                      )
                      and (
                        upper(o.externalId) like concat('%', :queryUpper, '%')
                        or upper(o.severity) like concat('%', :queryUpper, '%')
                        or upper(coalesce(v.title, '')) like concat('%', :queryUpper, '%')
                        or upper(coalesce(v.descriptionSnippet, '')) like concat('%', :queryUpper, '%')
                      )
                    """
    )
    Page<OrgCveRecord> findExposurePage(
            @Param("tenant") Tenant tenant,
            @Param("queryUpper") String queryUpper,
            @Param("inKev") Boolean inKev,
            Pageable pageable
    );

    @Query("""
            select
              count(o) as reviewQueueCount,
              sum(case when o.impactState in (
                    com.prototype.vulnwatch.domain.ImpactState.UNKNOWN,
                    com.prototype.vulnwatch.domain.ImpactState.UNDER_INVESTIGATION
                  ) then 1 else 0 end) as applicableCount,
              sum(case when o.impacted = true then 1 else 0 end) as impactedCount,
              sum(case when o.impactState = com.prototype.vulnwatch.domain.ImpactState.UNDER_INVESTIGATION then 1 else 0 end) as underInvestigationCount,
              sum(case when o.impactState in (
                    com.prototype.vulnwatch.domain.ImpactState.FIXED,
                    com.prototype.vulnwatch.domain.ImpactState.NOT_IMPACTED
                  ) then 1 else 0 end) as resolvedCount
            from OrgCveRecord o
            where o.tenant = :tenant
              and (
                o.impacted = true
                or o.impactState = com.prototype.vulnwatch.domain.ImpactState.UNKNOWN
                or o.impactState = com.prototype.vulnwatch.domain.ImpactState.UNDER_INVESTIGATION
              )
            """)
    Optional<ExposureSummaryRow> summarizeExposureCounts(@Param("tenant") Tenant tenant);

    default Optional<OrgCveRecord> findByTenantIdAndVulnerability(Long tenantId, Vulnerability vulnerability) {
        return findByTenantIdAndVulnerability(toTenantUuid(tenantId), vulnerability);
    }

    private static UUID toTenantUuid(Long tenantId) {
        return tenantId == null ? null : new UUID(0L, tenantId);
    }
}
