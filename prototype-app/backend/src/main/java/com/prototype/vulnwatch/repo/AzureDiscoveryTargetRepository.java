package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.AzureDiscoveryConfig;
import com.prototype.vulnwatch.domain.AzureDiscoveryTarget;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AzureDiscoveryTargetRepository extends JpaRepository<AzureDiscoveryTarget, UUID> {
    List<AzureDiscoveryTarget> findByConfigOrderBySubscriptionNameAscSubscriptionIdAsc(AzureDiscoveryConfig config);
    List<AzureDiscoveryTarget> findByConfigAndEnabledTrueOrderBySubscriptionNameAscSubscriptionIdAsc(AzureDiscoveryConfig config);
    Optional<AzureDiscoveryTarget> findByIdAndTenant_Id(UUID id, UUID tenantId);
    long countByConfig(AzureDiscoveryConfig config);
    long countByTenant_Id(UUID tenantId);
}
