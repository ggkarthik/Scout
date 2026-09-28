package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.BomIngestionRecord;
import com.prototype.vulnwatch.domain.BomStatus;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BomIngestionRecordRepository extends JpaRepository<BomIngestionRecord, UUID> {

    List<BomIngestionRecord> findByTenant_IdOrderByIngestedAtDesc(UUID tenantId, Pageable pageable);

    List<BomIngestionRecord> findByTenant_IdAndStatusOrderByIngestedAtDesc(UUID tenantId, BomStatus status, Pageable pageable);

    List<BomIngestionRecord> findByTenant_IdAndStatus(UUID tenantId, BomStatus status);

    List<BomIngestionRecord> findByTenant_IdAndAssetIdInAndStatusOrderByIngestedAtDesc(
            UUID tenantId,
            Collection<UUID> assetIds,
            BomStatus status
    );

    List<BomIngestionRecord> findByTenant_IdAndAssetIdAndStatusOrderByIngestedAtDesc(
            UUID tenantId,
            UUID assetId,
            BomStatus status
    );

    long countByTenant_IdAndStatus(UUID tenantId, BomStatus status);
}
