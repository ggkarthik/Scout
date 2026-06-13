package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.CampaignWatchlistEntry;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CampaignWatchlistEntryRepository extends JpaRepository<CampaignWatchlistEntry, UUID> {
    List<CampaignWatchlistEntry> findAllByCampaign_IdOrderByCreatedAtAsc(UUID campaignId);
}
