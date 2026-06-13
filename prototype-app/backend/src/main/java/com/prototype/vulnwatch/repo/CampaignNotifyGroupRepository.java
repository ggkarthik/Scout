package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.CampaignNotifyGroup;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CampaignNotifyGroupRepository extends JpaRepository<CampaignNotifyGroup, UUID> {
    List<CampaignNotifyGroup> findAllByCampaign_IdOrderByGroupNameAsc(UUID campaignId);
}
