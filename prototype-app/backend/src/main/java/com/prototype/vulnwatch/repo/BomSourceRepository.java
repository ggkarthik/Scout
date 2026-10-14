package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.BomSource;
import com.prototype.vulnwatch.domain.BomSourceState;
import com.prototype.vulnwatch.domain.BomType;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Queries are not tenant-qualified on purpose: TenantAwareDataSource pins search_path and
 * app.current_tenant_id per connection, and row-level security enforces the boundary.
 */
@Repository
public interface BomSourceRepository extends JpaRepository<BomSource, UUID> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select s from BomSource s where s.id = :id")
    Optional<BomSource> findForUpdate(@Param("id") UUID id);

    @Query("select s.id from BomSource s where s.sourceKey = :key")
    Optional<UUID> findIdBySourceKey(@Param("key") String key);

    /** Update only scheduling state; a detached worker snapshot must not overwrite the BOM revision. */
    @Modifying
    @Transactional
    @Query("update BomSource s set s.state = :state where s.id = :id")
    int updateSchedulingState(@Param("id") UUID id,
            @Param("state") BomSourceState state);

    /** Automated callers resolve their own source by its deterministic key. */
    Optional<BomSource> findBySourceKey(String sourceKey);

    List<BomSource> findByAssetIdAndBomType(UUID assetId, BomType bomType);

    List<BomSource> findByAssetId(UUID assetId);

    List<BomSource> findByState(BomSourceState state);

    Optional<BomSource> findByCurrentBomId(UUID currentBomId);
}
