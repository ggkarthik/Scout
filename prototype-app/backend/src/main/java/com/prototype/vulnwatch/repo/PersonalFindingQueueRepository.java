package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.PersonalFindingQueue;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PersonalFindingQueueRepository extends JpaRepository<PersonalFindingQueue, UUID> {
    List<PersonalFindingQueue> findByTenantIdAndOwnerUserIdOrderByDisplayOrderAscCreatedAtAsc(UUID tenantId, UUID ownerUserId);
    Optional<PersonalFindingQueue> findByIdAndTenantIdAndOwnerUserId(UUID id, UUID tenantId, UUID ownerUserId);
    boolean existsByTenantIdAndOwnerUserIdAndQueueKeyIgnoreCase(UUID tenantId, UUID ownerUserId, String queueKey);
    boolean existsByTenantIdAndOwnerUserIdAndTitleIgnoreCase(UUID tenantId, UUID ownerUserId, String title);
}
