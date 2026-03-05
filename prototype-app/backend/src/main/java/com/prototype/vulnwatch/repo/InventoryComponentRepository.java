package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.Tenant;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface InventoryComponentRepository extends JpaRepository<InventoryComponent, UUID> {
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
    List<InventoryComponent> findByTenantAndSoftwareModel_IdIn(Tenant tenant, Collection<UUID> softwareModelIds);
    @Query("""
            select c
            from InventoryComponent c
            left join c.sbomUpload u
            where c.tenant = :tenant
              and (:assetType is null or c.asset.type = :assetType)
              and (:componentStatus is null or c.componentStatus = :componentStatus)
              and (:sourceSystem is null or lower(coalesce(u.ingestionSourceSystem, '')) = lower(:sourceSystem))
            """)
    Page<InventoryComponent> findPageByFilters(
            @Param("tenant") Tenant tenant,
            @Param("assetType") AssetType assetType,
            @Param("componentStatus") InventoryComponentStatus componentStatus,
            @Param("sourceSystem") String sourceSystem,
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

    void deleteByAsset(Asset asset);
}
