package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.SoftwareInventoryItem;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface SoftwareInventoryItemRepository extends JpaRepository<SoftwareInventoryItem, UUID> {
    List<SoftwareInventoryItem> findByComponent_IdIn(Collection<UUID> componentIds);

    long countByTenant_IdAndComponent_IdIn(UUID tenantId, Collection<UUID> componentIds);

    @Query("""
            select distinct item.component.id
            from SoftwareInventoryItem item
            where item.tenant.id = :tenantId
              and item.component.id in :componentIds
            """)
    Set<UUID> findDistinctComponentIdsByTenantIdAndComponentIds(
            @Param("tenantId") UUID tenantId,
            @Param("componentIds") Collection<UUID> componentIds
    );

    @Query("""
            select item from SoftwareInventoryItem item
            join fetch item.component ic
            where item.tenant.id = :tenantId
              and item.componentStatus = com.prototype.vulnwatch.domain.InventoryComponentStatus.ACTIVE
              and (lower(item.packageName) like lower(concat('%', :term, '%'))
                   or lower(ic.packageName) like lower(concat('%', :term, '%')))
            """)
    List<SoftwareInventoryItem> searchActiveByPackageNameContaining(
            @Param("tenantId") UUID tenantId,
            @Param("term") String term
    );
}
