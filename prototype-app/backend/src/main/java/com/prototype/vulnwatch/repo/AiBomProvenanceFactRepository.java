package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.AiBomProvenanceFact;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

/** See {@link BomSourceRepository} on why these are not tenant-qualified. */
@Repository
public interface AiBomProvenanceFactRepository extends JpaRepository<AiBomProvenanceFact, UUID> {

    Optional<AiBomProvenanceFact> findByTenantIdAndAssetIdAndFactKey(
            UUID tenantId, UUID assetId, String factKey);
}
