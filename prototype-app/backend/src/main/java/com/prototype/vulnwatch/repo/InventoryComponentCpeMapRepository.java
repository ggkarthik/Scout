package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentCpeMap;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.Tenant;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface InventoryComponentCpeMapRepository extends JpaRepository<InventoryComponentCpeMap, UUID> {

    interface CpeComponentRow {
        UUID getCpeId();
        UUID getComponentId();
    }

    interface TenantComponentRow {
        UUID getTenantId();
        UUID getComponentId();
    }

    List<InventoryComponentCpeMap> findByComponent(InventoryComponent component);

    List<InventoryComponentCpeMap> findByComponent_IdIn(Collection<UUID> componentIds);

    List<InventoryComponentCpeMap> findByTenant_IdAndCpeDim_IdIn(UUID tenantId, Collection<UUID> cpeIds);

    List<InventoryComponentCpeMap> findByTenant_IdAndComponent_IdIn(UUID tenantId, Collection<UUID> componentIds);

    List<InventoryComponentCpeMap> findByComponent_Id(UUID componentId);

    @Query("""
            select distinct m.tenant.id
            from InventoryComponentCpeMap m
            where m.cpeDim.id in :cpeIds
            """)
    Set<UUID> findDistinctTenantIdsByCpeIds(@Param("cpeIds") Collection<UUID> cpeIds);

    @Query("""
            select distinct m.component.id
            from InventoryComponentCpeMap m
            where m.tenant.id = :tenantId
              and m.cpeDim.id in :cpeIds
            """)
    Set<UUID> findDistinctComponentIdsByTenantIdAndCpeIds(
            @Param("tenantId") UUID tenantId,
            @Param("cpeIds") Collection<UUID> cpeIds
    );

    @Query("""
            select distinct
              m.tenant.id as tenantId,
              m.component.id as componentId
            from InventoryComponentCpeMap m
            where m.cpeDim.id in :cpeIds
            """)
    List<TenantComponentRow> findDistinctTenantComponentRowsByCpeIds(
            @Param("cpeIds") Collection<UUID> cpeIds
    );

    @Query("""
            select distinct
              m.cpeDim.id as cpeId,
              m.component.id as componentId
            from InventoryComponentCpeMap m
            where m.tenant.id = :tenantId
              and m.cpeDim.id in :cpeIds
            """)
    List<CpeComponentRow> findDistinctCpeComponentRowsByTenantIdAndCpeIds(
            @Param("tenantId") UUID tenantId,
            @Param("cpeIds") Collection<UUID> cpeIds
    );

    @Query("""
            select count(distinct m.component.id)
            from InventoryComponentCpeMap m
            where m.tenant = :tenant
              and m.component.componentStatus = :componentStatus
            """)
    long countDistinctComponentIdsByTenantAndComponentStatus(
            @Param("tenant") Tenant tenant,
            @Param("componentStatus") InventoryComponentStatus componentStatus
    );

    void deleteByComponent(InventoryComponent component);

}
