package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.CbomPostureSummary;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CbomPostureSummaryRepository extends JpaRepository<CbomPostureSummary, UUID> {

    Optional<CbomPostureSummary> findByTenant_IdAndAsset_Id(UUID tenantId, UUID assetId);

    List<CbomPostureSummary> findByTenant_IdOrderByPostureScoreDesc(UUID tenantId);
}
