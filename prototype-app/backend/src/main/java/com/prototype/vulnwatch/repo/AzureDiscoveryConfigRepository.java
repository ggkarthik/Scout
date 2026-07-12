package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.AzureDiscoveryConfig;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AzureDiscoveryConfigRepository extends JpaRepository<AzureDiscoveryConfig, UUID> {

    Optional<AzureDiscoveryConfig> findByTenant_IdAndSourceSystemIgnoreCase(UUID tenantId, String sourceSystem);

    Optional<AzureDiscoveryConfig> findBySourceSystemIgnoreCase(String sourceSystem);

    List<AzureDiscoveryConfig> findByEnabledTrueAndAutoSyncEnabledTrueOrderByUpdatedAtAsc();

    long countByTenant_Id(UUID tenantId);
}
