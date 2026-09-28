package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.BomSource;
import com.prototype.vulnwatch.domain.BomSourceState;
import com.prototype.vulnwatch.domain.BomType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Queries are not tenant-qualified on purpose: TenantAwareDataSource pins search_path and
 * app.current_tenant_id per connection, and row-level security enforces the boundary.
 */
@Repository
public interface BomSourceRepository extends JpaRepository<BomSource, UUID> {

    List<BomSource> findByAssetIdAndBomType(UUID assetId, BomType bomType);

    List<BomSource> findByAssetId(UUID assetId);

    List<BomSource> findByState(BomSourceState state);

    Optional<BomSource> findByCurrentBomId(UUID currentBomId);
}
