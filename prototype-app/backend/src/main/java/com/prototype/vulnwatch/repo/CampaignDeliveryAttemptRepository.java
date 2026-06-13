package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.CampaignDeliveryAttempt;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CampaignDeliveryAttemptRepository extends JpaRepository<CampaignDeliveryAttempt, UUID> {
    List<CampaignDeliveryAttempt> findAllByCampaign_IdOrderByCreatedAtDesc(UUID campaignId);
}
