package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.AssetFixStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AssetFixStatusRepository extends JpaRepository<AssetFixStatus, UUID> {

    @Query("""
        SELECT afs FROM AssetFixStatus afs
        WHERE afs.tenantId = :tenantId
        AND afs.asset.id = :assetId
        AND afs.fixId = :fixId
        """)
    Optional<AssetFixStatus> findByTenantAndAssetAndFix(
        @Param("tenantId") UUID tenantId,
        @Param("assetId") UUID assetId,
        @Param("fixId") UUID fixId
    );

    @Query("""
        SELECT afs FROM AssetFixStatus afs
        WHERE afs.tenantId = :tenantId
        AND afs.fixId = :fixId
        """)
    List<AssetFixStatus> findByTenantAndFix(
        @Param("tenantId") UUID tenantId,
        @Param("fixId") UUID fixId
    );

    @Query("""
        SELECT afs FROM AssetFixStatus afs
        WHERE afs.tenantId = :tenantId
        AND afs.asset.id = :assetId
        """)
    List<AssetFixStatus> findByTenantAndAsset(
        @Param("tenantId") UUID tenantId,
        @Param("assetId") UUID assetId
    );

    @Query("""
        SELECT afs FROM AssetFixStatus afs
        WHERE afs.tenantId = :tenantId
        AND afs.deploymentStatus = :status
        """)
    List<AssetFixStatus> findByTenantAndDeploymentStatus(
        @Param("tenantId") UUID tenantId,
        @Param("status") AssetFixStatus.DeploymentStatus status
    );

    @Query("""
        SELECT COUNT(afs) FROM AssetFixStatus afs
        WHERE afs.tenantId = :tenantId
        AND afs.fixId = :fixId
        AND afs.deploymentStatus = 'DEPLOYED'
        """)
    long countDeployedByTenantAndFix(
        @Param("tenantId") UUID tenantId,
        @Param("fixId") UUID fixId
    );

    @Query("""
        SELECT COUNT(afs) FROM AssetFixStatus afs
        WHERE afs.tenantId = :tenantId
        AND afs.fixId = :fixId
        AND afs.applicable = true
        """)
    long countApplicableByTenantAndFix(
        @Param("tenantId") UUID tenantId,
        @Param("fixId") UUID fixId
    );

    @Query("""
        SELECT afs FROM AssetFixStatus afs
        WHERE afs.tenantId = :tenantId
        """)
    List<AssetFixStatus> findByTenantId(
        @Param("tenantId") UUID tenantId
    );
}
