package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.GithubAdvisorySyncStateEntity;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface GithubAdvisorySyncStateRepository extends JpaRepository<GithubAdvisorySyncStateEntity, UUID> {

    Optional<GithubAdvisorySyncStateEntity> findBySyncType(String syncType);

    @Query("SELECT g FROM GithubAdvisorySyncStateEntity g WHERE g.syncType = :syncType")
    Optional<GithubAdvisorySyncStateEntity> findBySyncTypeQuery(@Param("syncType") String syncType);

    @Query("SELECT g FROM GithubAdvisorySyncStateEntity g WHERE g.status = :status")
    List<GithubAdvisorySyncStateEntity> findByStatus(@Param("status") String status);

    @Query("SELECT g FROM GithubAdvisorySyncStateEntity g ORDER BY g.lastFullSyncAt DESC LIMIT 1")
    Optional<GithubAdvisorySyncStateEntity> findLatestFullSync();

    @Query("SELECT g FROM GithubAdvisorySyncStateEntity g ORDER BY g.lastIncrementalSyncAt DESC LIMIT 1")
    Optional<GithubAdvisorySyncStateEntity> findLatestIncrementalSync();
}
