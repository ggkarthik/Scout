package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.CbomComponent;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface CbomComponentRepository extends JpaRepository<CbomComponent, UUID> {

    Optional<CbomComponent> findByTenant_IdAndSourceBom_IdAndComponentFingerprint(
            UUID tenantId,
            UUID sourceBomId,
            String componentFingerprint
    );

    List<CbomComponent> findByTenant_IdAndAsset_IdAndActiveTrueOrderByRiskScoreDescNameAsc(
            UUID tenantId,
            UUID assetId,
            Pageable pageable
    );

    List<CbomComponent> findByTenant_IdAndAsset_IdAndActiveTrue(UUID tenantId, UUID assetId);

    List<CbomComponent> findByTenant_IdAndSourceBom_IdAndActiveTrue(UUID tenantId, UUID sourceBomId);

    @Modifying
    @Query("UPDATE CbomComponent c SET c.active = false WHERE c.sourceBom.id = :sourceBomId AND c.active = true")
    int softDeleteBySourceBomId(@Param("sourceBomId") UUID sourceBomId);

    long countByTenant_IdAndAsset_IdAndActiveTrue(UUID tenantId, UUID assetId);

    List<CbomComponent> findByIdInAndTenant_Id(Collection<UUID> ids, UUID tenantId);
}
