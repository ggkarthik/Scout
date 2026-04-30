package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.SccmCmdbConfig;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SccmCmdbConfigRepository extends JpaRepository<SccmCmdbConfig, UUID> {
    Optional<SccmCmdbConfig> findByTenant_IdAndSourceSystemIgnoreCase(UUID tenantId, String sourceSystem);
    List<SccmCmdbConfig> findByEnabledTrueAndAutoSyncEnabledTrueOrderByUpdatedAtAsc();
    long countByTenant_Id(UUID tenantId);
}
