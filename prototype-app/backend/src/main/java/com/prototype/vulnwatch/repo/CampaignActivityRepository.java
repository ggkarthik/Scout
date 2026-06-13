package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.CampaignActivity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CampaignActivityRepository extends JpaRepository<CampaignActivity, UUID> {
    List<CampaignActivity> findAllByCampaign_IdOrderByCreatedAtDesc(UUID campaignId);
}
