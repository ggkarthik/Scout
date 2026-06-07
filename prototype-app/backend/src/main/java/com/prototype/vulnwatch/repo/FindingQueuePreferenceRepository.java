package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.FindingQueuePreference;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface FindingQueuePreferenceRepository extends JpaRepository<FindingQueuePreference, UUID> {
    Optional<FindingQueuePreference> findByTenantIdAndOwnerUserId(UUID tenantId, UUID ownerUserId);
}
