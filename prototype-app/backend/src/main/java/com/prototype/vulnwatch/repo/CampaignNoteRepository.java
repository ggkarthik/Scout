package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.CampaignNote;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CampaignNoteRepository extends JpaRepository<CampaignNote, UUID> {
    List<CampaignNote> findAllByCampaign_IdOrderByCreatedAtDesc(UUID campaignId);
}
