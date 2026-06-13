package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.Campaign;
import com.prototype.vulnwatch.domain.CampaignStatus;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CampaignRepository extends JpaRepository<Campaign, UUID> {
    List<Campaign> findAllByTenant_IdOrderByUpdatedAtDesc(UUID tenantId);
    List<Campaign> findAllByTenant_IdAndStatusOrderByUpdatedAtDesc(UUID tenantId, CampaignStatus status);
    Optional<Campaign> findByIdAndTenant_Id(UUID id, UUID tenantId);
}
