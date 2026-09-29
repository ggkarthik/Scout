package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.BomAssetBackfillState;
import com.prototype.vulnwatch.domain.BomBackfillState;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/** See {@link BomSourceRepository} on why these are not tenant-qualified. */
@Repository
public interface BomAssetBackfillStateRepository
        extends JpaRepository<BomAssetBackfillState, UUID> {

    Optional<BomAssetBackfillState> findByAssetId(UUID assetId);

    List<BomAssetBackfillState> findByState(BomBackfillState state);

    long countByState(BomBackfillState state);
}
