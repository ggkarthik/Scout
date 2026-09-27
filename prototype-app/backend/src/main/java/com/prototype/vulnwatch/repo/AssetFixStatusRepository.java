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

    Optional<AssetFixStatus> findByAssetIdAndFixId(UUID assetId, UUID fixId);

    List<AssetFixStatus> findByFixId(UUID fixId);

    List<AssetFixStatus> findByAssetId(UUID assetId);

    List<AssetFixStatus> findByDeploymentStatus(AssetFixStatus.DeploymentStatus status);

    @Query("""
        SELECT COUNT(afs) FROM AssetFixStatus afs
        WHERE afs.fixId = :fixId
        AND afs.deploymentStatus = 'DEPLOYED'
        """)
    long countDeployedByFix(@Param("fixId") UUID fixId);

    @Query("""
        SELECT COUNT(afs) FROM AssetFixStatus afs
        WHERE afs.fixId = :fixId
        AND afs.applicable = true
        """)
    long countApplicableByFix(@Param("fixId") UUID fixId);
}
