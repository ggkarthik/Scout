package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.Tenant;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface InventoryComponentRepository extends JpaRepository<InventoryComponent, UUID> {

    interface NormalizationAggregateRow {
        long getTotal();
        long getNormalizedNameCount();
        long getNormalizedVersionCount();
        long getSoftwareIdentityCount();
        long getSoftwareModelCount();
        long getUnresolvedCount();
    }

    interface TenantComponentLookupRow {
        UUID getTenantId();
        UUID getComponentId();
    }

    @Query("""
            select
              count(c) as total,
              sum(case when c.normalizedName is not null and trim(c.normalizedName) <> '' then 1 else 0 end) as normalizedNameCount,
              sum(case when c.normalizedVersion is not null and trim(c.normalizedVersion) <> '' then 1 else 0 end) as normalizedVersionCount,
              sum(case when c.softwareIdentity is not null then 1 else 0 end) as softwareIdentityCount,
              sum(case when c.softwareModelResult is not null and upper(c.softwareModelResult) like 'MATCHED:%' then 1 else 0 end) as softwareModelCount,
              sum(case when c.softwareModelResult is null or trim(c.softwareModelResult) = '' or upper(c.softwareModelResult) like 'UNRESOLVED%' then 1 else 0 end) as unresolvedCount
            from InventoryComponent c
            where c.tenant = :tenant
              and c.componentStatus = :status
            """)
    Optional<NormalizationAggregateRow> findNormalizationAggregate(
            @Param("tenant") Tenant tenant,
            @Param("status") InventoryComponentStatus status
    );

    @Query("""
            select
              count(c) as total,
              sum(case when c.normalizedName is not null and trim(c.normalizedName) <> '' then 1 else 0 end) as normalizedNameCount,
              sum(case when c.normalizedVersion is not null and trim(c.normalizedVersion) <> '' then 1 else 0 end) as normalizedVersionCount,
              sum(case when c.softwareIdentity is not null then 1 else 0 end) as softwareIdentityCount,
              sum(case when c.softwareModelResult is not null and upper(c.softwareModelResult) like 'MATCHED:%' then 1 else 0 end) as softwareModelCount,
              sum(case when c.softwareModelResult is null or trim(c.softwareModelResult) = '' or upper(c.softwareModelResult) like 'UNRESOLVED%' then 1 else 0 end) as unresolvedCount
            from InventoryComponent c
            where c.tenant = :tenant
              and c.componentStatus = :status
              and (c.lastObservedAt is null or c.lastObservedAt < :before)
            """)
    Optional<NormalizationAggregateRow> findNormalizationAggregateBeforeLastObservedAt(
            @Param("tenant") Tenant tenant,
            @Param("status") InventoryComponentStatus status,
            @Param("before") Instant before
    );
    List<InventoryComponent> findByTenant(Tenant tenant);
    List<InventoryComponent> findByTenantOrderByLastObservedAtDesc(Tenant tenant);
    List<InventoryComponent> findByComponentStatus(InventoryComponentStatus status);
    List<InventoryComponent> findByTenantAndComponentStatusOrderByLastObservedAtDesc(
            Tenant tenant,
            InventoryComponentStatus status
    );
    List<InventoryComponent> findByTenantAndAsset_TypeOrderByLastObservedAtDesc(
            Tenant tenant,
            AssetType assetType
    );
    List<InventoryComponent> findByTenantAndAsset_TypeAndComponentStatusOrderByLastObservedAtDesc(
            Tenant tenant,
            AssetType assetType,
            InventoryComponentStatus status
    );
    long countByTenant(Tenant tenant);
    long countByTenantAndComponentStatus(Tenant tenant, InventoryComponentStatus status);
    List<InventoryComponent> findByAsset(Asset asset);
    List<InventoryComponent> findByAssetAndComponentStatus(Asset asset, InventoryComponentStatus status);
    @Query("""
            select c
            from InventoryComponent c
            left join c.sbomUpload u
            left join c.softwareIdentity s
            where c.tenant = :tenant
              and (:assetTypes is null or c.asset.type in :assetTypes)
              and (:componentStatuses is null or c.componentStatus in :componentStatuses)
              and (:normalizedSourceSystems is null or lower(coalesce(u.ingestionSourceSystem, '')) in :normalizedSourceSystems)
              and (:normalizedEcosystems is null or lower(coalesce(c.ecosystem, '')) in :normalizedEcosystems)
              and (
                :normalizedQueryPattern is null
                or lower(coalesce(c.asset.name, '')) like :normalizedQueryPattern
                or lower(coalesce(c.asset.identifier, '')) like :normalizedQueryPattern
                or lower(coalesce(c.packageName, '')) like :normalizedQueryPattern
                or lower(coalesce(c.normalizedName, '')) like :normalizedQueryPattern
                or lower(coalesce(s.displayName, '')) like :normalizedQueryPattern
                or lower(coalesce(c.purl, '')) like :normalizedQueryPattern
              )
            """)
    Page<InventoryComponent> findPageByFilters(
            @Param("tenant") Tenant tenant,
            @Param("assetTypes") Collection<AssetType> assetTypes,
            @Param("componentStatuses") Collection<InventoryComponentStatus> componentStatuses,
            @Param("normalizedSourceSystems") Collection<String> normalizedSourceSystems,
            @Param("normalizedEcosystems") Collection<String> normalizedEcosystems,
            @Param("normalizedQueryPattern") String normalizedQueryPattern,
            Pageable pageable
    );

    @Query("""
            select distinct c.asset.type
            from InventoryComponent c
            where c.tenant = :tenant
            """)
    List<AssetType> findDistinctAssetTypesByTenant(@Param("tenant") Tenant tenant);

    @Query("""
            select distinct c.componentStatus
            from InventoryComponent c
            where c.tenant = :tenant
            """)
    List<InventoryComponentStatus> findDistinctComponentStatusesByTenant(@Param("tenant") Tenant tenant);

    @Query("""
            select distinct lower(u.ingestionSourceSystem)
            from InventoryComponent c
            left join c.sbomUpload u
            where c.tenant = :tenant
              and u.ingestionSourceSystem is not null
              and trim(u.ingestionSourceSystem) <> ''
            """)
    List<String> findDistinctSourceSystemsByTenant(@Param("tenant") Tenant tenant);

    @Query("""
            select distinct lower(c.ecosystem)
            from InventoryComponent c
            where c.tenant = :tenant
              and c.ecosystem is not null
              and trim(c.ecosystem) <> ''
            """)
    List<String> findDistinctEcosystemsByTenant(@Param("tenant") Tenant tenant);

    void deleteByAsset(Asset asset);

    @Query("""
            select distinct c.tenant.id
            from InventoryComponent c
            where c.normalizedPurl in :purls
            """)
    Set<UUID> findDistinctTenantIdsByNormalizedPurlIn(@Param("purls") Collection<String> purls);

    @Query("""
            select distinct c.id
            from InventoryComponent c
            where c.tenant.id = :tenantId
              and c.normalizedPurl in :purls
            """)
    Set<UUID> findDistinctIdsByTenantIdAndNormalizedPurlIn(
            @Param("tenantId") UUID tenantId,
            @Param("purls") Collection<String> purls
    );

    @Query("""
            select distinct
              c.tenant.id as tenantId,
              c.id as componentId
            from InventoryComponent c
            where c.normalizedPurl in :purls
            """)
    List<TenantComponentLookupRow> findDistinctTenantComponentRowsByNormalizedPurlIn(
            @Param("purls") Collection<String> purls
    );

    @Query("""
            select distinct c.tenant.id
            from InventoryComponent c
            where c.coordKey in :coordKeys
            """)
    Set<UUID> findDistinctTenantIdsByCoordKeyIn(@Param("coordKeys") Collection<String> coordKeys);

    @Query("""
            select distinct c.id
            from InventoryComponent c
            where c.tenant.id = :tenantId
              and c.coordKey in :coordKeys
            """)
    Set<UUID> findDistinctIdsByTenantIdAndCoordKeyIn(
            @Param("tenantId") UUID tenantId,
            @Param("coordKeys") Collection<String> coordKeys
    );

    @Query("""
            select distinct
              c.tenant.id as tenantId,
              c.id as componentId
            from InventoryComponent c
            where c.coordKey in :coordKeys
            """)
    List<TenantComponentLookupRow> findDistinctTenantComponentRowsByCoordKeyIn(
            @Param("coordKeys") Collection<String> coordKeys
    );
}
