package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.SoftwareInventoryItem;
import com.prototype.vulnwatch.domain.Tenant;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface SoftwareInventoryItemRepository extends JpaRepository<SoftwareInventoryItem, UUID> {
    List<SoftwareInventoryItem> findByTenantAndComponent_IdIn(Tenant tenant, Collection<UUID> componentIds);

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
}
