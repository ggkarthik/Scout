package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.AwsDiscoveryConfig;
import com.prototype.vulnwatch.domain.AwsDiscoveryTarget;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AwsDiscoveryTargetRepository extends JpaRepository<AwsDiscoveryTarget, UUID> {
    List<AwsDiscoveryTarget> findByConfigOrderByAccountNameAscAccountIdAsc(AwsDiscoveryConfig config);
    List<AwsDiscoveryTarget> findByConfigAndEnabledTrueOrderByAccountNameAscAccountIdAsc(AwsDiscoveryConfig config);
    Optional<AwsDiscoveryTarget> findByIdAndTenant_Id(UUID id, UUID tenantId);
    long countByConfig(AwsDiscoveryConfig config);
}
