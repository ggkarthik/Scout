package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.dto.TopFindingMetricResponse;
import java.time.Instant;
import java.util.Collection;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface FindingRepository extends JpaRepository<Finding, UUID>, JpaSpecificationExecutor<Finding> {
    interface VulnerabilityFindingCountRow {
        UUID getVulnerabilityId();
        long getFindingCount();
    }

    List<Finding> findByTenantOrderByUpdatedAtDesc(Tenant tenant);
    Page<Finding> findByTenantOrderByUpdatedAtDesc(Tenant tenant, Pageable pageable);
    List<Finding> findByTenantAndStatusOrderByUpdatedAtDesc(Tenant tenant, FindingStatus status);
    List<Finding> findByStatusAndSuppressedUntilBefore(FindingStatus status, Instant before);
    List<Finding> findByAsset(Asset asset);
    List<Finding> findByAssetAndStatus(Asset asset, FindingStatus status);
    List<Finding> findByComponent(InventoryComponent component);
    List<Finding> findByTenant_IdAndVulnerability_Id(UUID tenantId, UUID vulnerabilityId);
    @Query("""
            select distinct f.tenant.id
            from Finding f
            where f.vulnerability.id = :vulnerabilityId
            """)
    Set<UUID> findDistinctTenantIdsByVulnerabilityId(@Param("vulnerabilityId") UUID vulnerabilityId);

    @Query("""
            select distinct f.component.id
            from Finding f
            where f.tenant = :tenant
              and f.status = :status
              and f.component is not null
            """)
    Set<UUID> findDistinctComponentIdsByTenantAndStatus(
            @Param("tenant") Tenant tenant,
            @Param("status") FindingStatus status
    );
    long countByVulnerabilityAndStatus(Vulnerability vulnerability, FindingStatus status);
    void deleteByAsset(Asset asset);
    long countByTenantAndStatus(Tenant tenant, FindingStatus status);
    long countByTenantAndStatusAndRiskScoreGreaterThanEqual(Tenant tenant, FindingStatus status, double minRiskScore);
    long countByTenantAndStatusAndConfidenceScoreGreaterThanEqual(Tenant tenant, FindingStatus status, double minConfidence);

    @Query("""
            select count(f)
            from Finding f
            join f.vulnerability v
            where f.tenant = :tenant and f.status = :status and upper(v.severity) = upper(:severity)
            """)
    long countByTenantAndStatusAndSeverity(
            @Param("tenant") Tenant tenant,
            @Param("status") FindingStatus status,
            @Param("severity") String severity
    );

    @Query("""
            select coalesce(avg(f.riskScore), 0)
            from Finding f
            where f.tenant = :tenant and f.status = :status
            """)
    double averageRiskScoreByTenantAndStatus(
            @Param("tenant") Tenant tenant,
            @Param("status") FindingStatus status
    );

    @Query("""
            select coalesce(avg(f.confidenceScore), 0)
            from Finding f
            where f.tenant = :tenant and f.status = :status
            """)
    double averageConfidenceScoreByTenantAndStatus(
            @Param("tenant") Tenant tenant,
            @Param("status") FindingStatus status
    );

    @Query("""
            select new com.prototype.vulnwatch.dto.TopFindingMetricResponse(v.externalId, count(f))
            from Finding f
            join f.vulnerability v
            where f.tenant = :tenant and f.status = :status
            group by v.externalId
            order by count(f) desc
            """)
    List<TopFindingMetricResponse> findTopVulnerabilitiesByTenantAndStatus(
            @Param("tenant") Tenant tenant,
            @Param("status") FindingStatus status,
            Pageable pageable
    );

    @Query("""
            select new com.prototype.vulnwatch.dto.TopFindingMetricResponse(
                concat(concat(lower(c.ecosystem), ':'), lower(c.packageName)),
                count(f)
            )
            from Finding f
            join f.component c
            where f.tenant = :tenant and f.status = :status
            group by c.ecosystem, c.packageName
            order by count(f) desc
            """)
    List<TopFindingMetricResponse> findTopInstalledComponentsByTenantAndStatus(
            @Param("tenant") Tenant tenant,
            @Param("status") FindingStatus status,
            Pageable pageable
    );

    @Query("""
            select new com.prototype.vulnwatch.dto.TopFindingMetricResponse(
                concat(concat(a.name, ' ('), concat(a.identifier, ')')),
                count(f)
            )
            from Finding f
            join f.asset a
            where f.tenant = :tenant and f.status = :status
            group by a.name, a.identifier
            order by count(f) desc
            """)
    List<TopFindingMetricResponse> findTopAssetsByTenantAndStatus(
            @Param("tenant") Tenant tenant,
            @Param("status") FindingStatus status,
            Pageable pageable
    );

    @Query("""
            select new com.prototype.vulnwatch.dto.TopFindingMetricResponse(
                concat(concat(concat(v.externalId, ' | '), lower(c.ecosystem)), concat(':', lower(c.packageName))),
                count(f)
            )
            from Finding f
            join f.vulnerability v
            join f.component c
            where f.tenant = :tenant and f.status = :status
            group by v.externalId, c.ecosystem, c.packageName
            order by count(f) desc
            """)
    List<TopFindingMetricResponse> findTopVulnerabilityProductIdentitiesByTenantAndStatus(
            @Param("tenant") Tenant tenant,
            @Param("status") FindingStatus status,
            Pageable pageable
    );

    @Query("""
            select f.vulnerability.id, count(f)
            from Finding f
            where f.status = :status
              and f.vulnerability.id in :vulnerabilityIds
            group by f.vulnerability.id
            """)
    List<Object[]> countByVulnerabilityIdsAndStatus(
            @Param("vulnerabilityIds") List<UUID> vulnerabilityIds,
            @Param("status") FindingStatus status
    );

    @Query("""
            select
              f.vulnerability.id as vulnerabilityId,
              count(f) as findingCount
            from Finding f
            where f.tenant = :tenant
              and f.status = :status
              and f.vulnerability.id in :vulnerabilityIds
            group by f.vulnerability.id
            """)
    List<VulnerabilityFindingCountRow> countByTenantAndVulnerabilityIdsAndStatus(
            @Param("tenant") Tenant tenant,
            @Param("vulnerabilityIds") Collection<UUID> vulnerabilityIds,
            @Param("status") FindingStatus status
    );

    @Query("""
            select count(distinct f.id)
            from Finding f
            where f.tenant = :tenant
              and f.status = :status
              and f.decisionState = :decisionState
              and exists (
                select 1
                from FindingEvent fe
                where fe.finding = f
                  and fe.eventType = :eventType
              )
            """)
    long countByTenantAndStatusAndDecisionStateWithEvent(
            @Param("tenant") Tenant tenant,
            @Param("status") FindingStatus status,
            @Param("decisionState") FindingDecisionState decisionState,
            @Param("eventType") String eventType
    );

    @Query("""
            select distinct upper(v.severity)
            from Finding f
            join f.vulnerability v
            where f.tenant = :tenant
              and v.severity is not null
              and trim(v.severity) <> ''
            """)
    List<String> findDistinctSeveritiesByTenant(@Param("tenant") Tenant tenant);

    @Query("""
            select distinct f.status
            from Finding f
            where f.tenant = :tenant
            """)
    List<FindingStatus> findDistinctStatusesByTenant(@Param("tenant") Tenant tenant);

    @Query("""
            select distinct f.decisionState
            from Finding f
            where f.tenant = :tenant
            """)
    List<FindingDecisionState> findDistinctDecisionStatesByTenant(@Param("tenant") Tenant tenant);

    @Query("""
            select distinct lower(f.matchedBy)
            from Finding f
            where f.tenant = :tenant
              and f.matchedBy is not null
              and trim(f.matchedBy) <> ''
            """)
    List<String> findDistinctMatchMethodsByTenant(@Param("tenant") Tenant tenant);

    @Query("""
            select distinct f.vexStatus
            from Finding f
            where f.tenant = :tenant
              and f.vexStatus is not null
              and trim(f.vexStatus) <> ''
            """)
    List<String> findDistinctVexStatusesByTenant(@Param("tenant") Tenant tenant);

    @Query("""
            select distinct f.vexFreshness
            from Finding f
            where f.tenant = :tenant
              and f.vexFreshness is not null
              and trim(f.vexFreshness) <> ''
            """)
    List<String> findDistinctVexFreshnessByTenant(@Param("tenant") Tenant tenant);

    @Query("""
            select distinct f.vexProvider
            from Finding f
            where f.tenant = :tenant
              and f.vexProvider is not null
              and trim(f.vexProvider) <> ''
            """)
    List<String> findDistinctVexProvidersByTenant(@Param("tenant") Tenant tenant);
}
