package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.AwsDiscoveryConfig;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AwsDiscoveryConfigRepository extends JpaRepository<AwsDiscoveryConfig, UUID> {

    Optional<AwsDiscoveryConfig> findByTenant_IdAndSourceSystemIgnoreCase(UUID tenantId, String sourceSystem);

    List<AwsDiscoveryConfig> findByEnabledTrueAndAutoSyncEnabledTrueOrderByUpdatedAtAsc();
}
