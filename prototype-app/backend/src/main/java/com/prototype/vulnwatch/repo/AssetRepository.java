package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetState;
import com.prototype.vulnwatch.domain.Tenant;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AssetRepository extends JpaRepository<Asset, UUID> {
    List<Asset> findByTenant(Tenant tenant);
    long countByTenant(Tenant tenant);
    Optional<Asset> findByTenantAndIdentifier(Tenant tenant, String identifier);
    Optional<Asset> findByIdentifier(String identifier);
    List<Asset> findByState(AssetState state);

    @Query("""
            select a
            from Asset a
            where a.lastInventoryAt is not null
              and a.lastInventoryAt < :cutoff
              and a.state = com.prototype.vulnwatch.domain.AssetState.ACTIVE
            """)
    List<Asset> findActiveAssetsWithInventoryBefore(@Param("cutoff") Instant cutoff);
}
