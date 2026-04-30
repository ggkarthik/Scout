package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.ServiceNowCmdbConfig;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ServiceNowCmdbConfigRepository extends JpaRepository<ServiceNowCmdbConfig, UUID> {
    Optional<ServiceNowCmdbConfig> findByTenant_IdAndSourceSystemIgnoreCase(UUID tenantId, String sourceSystem);
    List<ServiceNowCmdbConfig> findByEnabledTrueAndAutoSyncEnabledTrueOrderByUpdatedAtAsc();
    long countByTenant_Id(UUID tenantId);
}
