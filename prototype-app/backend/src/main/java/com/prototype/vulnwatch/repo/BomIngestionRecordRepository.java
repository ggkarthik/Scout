package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.BomIngestionRecord;
import com.prototype.vulnwatch.domain.BomStatus;
import com.prototype.vulnwatch.domain.BomType;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface BomIngestionRecordRepository extends JpaRepository<BomIngestionRecord, UUID> {

    List<BomIngestionRecord> findByTenant_IdOrderByIngestedAtDesc(UUID tenantId, Pageable pageable);

    List<BomIngestionRecord> findByTenant_IdAndStatusOrderByIngestedAtDesc(UUID tenantId, BomStatus status, Pageable pageable);

    List<BomIngestionRecord> findByTenant_IdAndStatus(UUID tenantId, BomStatus status);

    List<BomIngestionRecord> findByTenant_IdAndAssetIdInAndStatusOrderByIngestedAtDesc(
            UUID tenantId,
            Collection<UUID> assetIds,
            BomStatus status
    );

    @Query("""
        SELECT r FROM BomIngestionRecord r
        WHERE r.tenant.id = :tenantId
          AND r.bomType = :bomType
          AND r.status = 'ACTIVE'
          AND r.assetId = :assetId
          AND ((:supplier IS NULL AND r.supplier IS NULL) OR r.supplier = :supplier)
        ORDER BY r.ingestedAt DESC
        """)
    List<BomIngestionRecord> findActiveForAsset(
            @Param("tenantId") UUID tenantId,
            @Param("bomType") BomType bomType,
            @Param("assetId") UUID assetId,
            @Param("supplier") String supplier,
            Pageable pageable
    );

    @Query("""
        SELECT r FROM BomIngestionRecord r
        WHERE r.tenant.id = :tenantId
          AND r.bomType = :bomType
          AND r.status = 'ACTIVE'
          AND r.assetId IS NULL
          AND ((:supplier IS NULL AND r.supplier IS NULL) OR r.supplier = :supplier)
          AND ((:sourceReference IS NULL AND r.sourceReference IS NULL) OR r.sourceReference = :sourceReference)
        ORDER BY r.ingestedAt DESC
        """)
    List<BomIngestionRecord> findActiveWithoutAsset(
            @Param("tenantId") UUID tenantId,
            @Param("bomType") BomType bomType,
            @Param("supplier") String supplier,
            @Param("sourceReference") String sourceReference,
            Pageable pageable
    );

    List<BomIngestionRecord> findByTenant_IdAndAssetIdAndStatusOrderByIngestedAtDesc(
            UUID tenantId,
            UUID assetId,
            BomStatus status
    );

    long countByTenant_IdAndStatus(UUID tenantId, BomStatus status);
}
