package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.Ci;
import com.prototype.vulnwatch.domain.SoftwareInstance;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SoftwareInstanceRepository extends JpaRepository<SoftwareInstance, UUID> {
    Optional<SoftwareInstance> findByCiAndNormalizedProductAndNormalizedVersionAndVersionEvidence(
            Ci ci,
            String normalizedProduct,
            String normalizedVersion,
            String versionEvidence
    );

    List<SoftwareInstance> findByCi(Ci ci);

    List<SoftwareInstance> findByInventoryComponent_IdIn(Collection<UUID> componentIds);

    List<SoftwareInstance> findByTenant_IdAndCi_IdIn(UUID tenantId, Collection<UUID> ciIds);

    List<SoftwareInstance> findByCi_IdOrderByDisplayNameAsc(UUID ciId);
}
