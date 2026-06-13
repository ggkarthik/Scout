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
          AND ((:assetId IS NULL AND r.assetId IS NULL) OR r.assetId = :assetId)
          AND r.supplier IS NULL
        ORDER BY r.ingestedAt DESC
        """)
    Optional<BomIngestionRecord> findActiveDuplicateWithoutSupplier(
            @Param("tenantId") UUID tenantId,
            @Param("bomType") BomType bomType,
            @Param("assetId") UUID assetId
    );

    @Query("""
        SELECT r FROM BomIngestionRecord r
        WHERE r.tenant.id = :tenantId
          AND r.bomType = :bomType
          AND r.status = 'ACTIVE'
          AND ((:assetId IS NULL AND r.assetId IS NULL) OR r.assetId = :assetId)
          AND r.supplier = :supplier
        ORDER BY r.ingestedAt DESC
        """)
    Optional<BomIngestionRecord> findActiveDuplicateWithSupplier(
            @Param("tenantId") UUID tenantId,
            @Param("bomType") BomType bomType,
            @Param("assetId") UUID assetId,
            @Param("supplier") String supplier
    );

    long countByTenant_IdAndStatus(UUID tenantId, BomStatus status);
}
