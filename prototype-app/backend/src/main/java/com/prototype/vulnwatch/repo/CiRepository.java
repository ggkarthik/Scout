package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.Ci;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CiRepository extends JpaRepository<Ci, UUID> {
    Optional<Ci> findBySysId(String sysId);

    List<Ci> findByTenant_IdAndSysIdIn(UUID tenantId, Collection<String> sysIds);
    List<Ci> findBySysIdIn(Collection<String> sysIds);

    List<Ci> findByTenant_IdOrderByDisplayNameAsc(UUID tenantId);
    List<Ci> findAllByOrderByDisplayNameAsc();

    Optional<Ci> findByTenant_IdAndAsset_Id(UUID tenantId, UUID assetId);
    Optional<Ci> findByAsset_Id(UUID assetId);

    List<Ci> findByTenant_IdAndAsset_IdIn(UUID tenantId, Collection<UUID> assetIds);
    List<Ci> findByAsset_IdIn(Collection<UUID> assetIds);
}
