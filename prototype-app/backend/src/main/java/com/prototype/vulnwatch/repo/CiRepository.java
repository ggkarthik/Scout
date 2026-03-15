package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.Ci;
import com.prototype.vulnwatch.domain.Tenant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CiRepository extends JpaRepository<Ci, UUID> {
    Optional<Ci> findByTenantAndSysId(Tenant tenant, String sysId);

    List<Ci> findByTenant_IdAndSysIdIn(UUID tenantId, Collection<String> sysIds);

    List<Ci> findByTenantAndDisplayNameIgnoreCase(Tenant tenant, String displayName);

    List<Ci> findByTenant_IdOrderByDisplayNameAsc(UUID tenantId);

    Optional<Ci> findByTenant_IdAndAsset_Id(UUID tenantId, UUID assetId);

    List<Ci> findByTenant_IdAndAsset_IdIn(UUID tenantId, Collection<UUID> assetIds);
}
