package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.SyncRun;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface SyncRunRepository extends JpaRepository<SyncRun, UUID> {
    List<SyncRun> findTop10ByOrderByStartedAtDesc();
    List<SyncRun> findByStatusIgnoreCase(String status);
    List<SyncRun> findByStartedAtGreaterThanEqual(Instant fromInclusive);
    Optional<SyncRun> findTopBySyncTypeIgnoreCaseOrderByStartedAtDesc(String syncType);

    @Query("""
            select r
            from SyncRun r
            where lower(r.status) in :statuses
            order by r.startedAt asc
            """)
    List<SyncRun> findQueueByStatuses(@Param("statuses") List<String> statuses);

    @Query("""
            select r
            from SyncRun r
            where lower(r.syncType) = lower(:syncType)
              and lower(r.status) in :statuses
            order by r.startedAt desc
            """)
    List<SyncRun> findActiveRunsBySyncType(
            @Param("syncType") String syncType,
            @Param("statuses") List<String> statuses
    );
}
