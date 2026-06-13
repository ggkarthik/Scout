package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.CampaignException;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CampaignExceptionRepository extends JpaRepository<CampaignException, UUID> {
    List<CampaignException> findAllByCampaign_IdOrderByRequestedAtDesc(UUID campaignId);
}
