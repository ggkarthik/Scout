package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.IngestionJob;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface IngestionJobRepository extends JpaRepository<IngestionJob, UUID> {

    interface StatusSummaryRow {
        long getQueuedCount();
        long getRunningCount();
        Instant getOldestVisibleQueuedAt();
        Instant getOldestRunningStartedAt();
    }

    @Query(value = """
            SELECT * FROM ingestion_jobs
             WHERE status = 'QUEUED'
               AND visible_at <= now()
             ORDER BY requested_at, id
             LIMIT :limit
             FOR UPDATE SKIP LOCKED
            """, nativeQuery = true)
    List<IngestionJob> pollPending(@Param("limit") int limit);

    @Query(value = """
            SELECT * FROM ingestion_jobs
             WHERE status = 'QUEUED'
               AND visible_at <= now()
               AND job_type <> :excludedJobType
             ORDER BY requested_at, id
             LIMIT :limit
             FOR UPDATE SKIP LOCKED
            """, nativeQuery = true)
    List<IngestionJob> pollPendingExcluding(
            @Param("excludedJobType") String excludedJobType,
            @Param("limit") int limit);

    @Query(value = """
            SELECT * FROM ingestion_jobs
             WHERE status = 'QUEUED'
               AND visible_at <= now()
               AND job_type NOT IN (:excludedJobTypes)
             ORDER BY requested_at, id
             LIMIT :limit
             FOR UPDATE SKIP LOCKED
            """, nativeQuery = true)
    List<IngestionJob> pollPendingExcludingJobTypes(
            @Param("excludedJobTypes") Collection<String> excludedJobTypes,
            @Param("limit") int limit);

    @Query(value = """
            SELECT * FROM ingestion_jobs
             WHERE status = 'QUEUED'
               AND visible_at <= now()
               AND job_type = :jobType
             ORDER BY requested_at, id
             LIMIT :limit
             FOR UPDATE SKIP LOCKED
            """, nativeQuery = true)
    List<IngestionJob> pollPendingByJobType(@Param("jobType") String jobType, @Param("limit") int limit);

    @Query(value = """
            SELECT * FROM ingestion_jobs
             WHERE dedupe_key = :dedupeKey
               AND status IN ('QUEUED', 'RUNNING')
             ORDER BY requested_at DESC, id DESC
             LIMIT 1
             FOR UPDATE
            """, nativeQuery = true)
    Optional<IngestionJob> findActiveByDedupeKeyForUpdate(@Param("dedupeKey") String dedupeKey);

    @Query("SELECT COUNT(j) FROM IngestionJob j WHERE j.status = :status")
    long countByStatusValue(@Param("status") String status);

    @Query("SELECT COUNT(j) FROM IngestionJob j WHERE j.status = :status AND j.jobType <> :excludedJobType")
    long countByStatusExcludingJobType(
            @Param("status") String status,
            @Param("excludedJobType") String excludedJobType);

    @Query("SELECT COUNT(j) FROM IngestionJob j WHERE j.status = :status AND j.jobType NOT IN :excludedJobTypes")
    long countByStatusExcludingJobTypes(
            @Param("status") String status,
            @Param("excludedJobTypes") Collection<String> excludedJobTypes);

    @Query("SELECT COUNT(j) FROM IngestionJob j WHERE j.status = :status AND j.jobType = :jobType")
    long countByStatusAndJobType(@Param("status") String status, @Param("jobType") String jobType);

    @Query(value = """
            select
              coalesce(sum(case when status = 'QUEUED' then 1 else 0 end), 0) as queuedCount,
              coalesce(sum(case when status = 'RUNNING' then 1 else 0 end), 0) as runningCount,
              min(case
                    when status = 'QUEUED' and visible_at <= :before
                    then visible_at
                  end) as oldestVisibleQueuedAt,
              min(case
                    when status = 'RUNNING'
                    then started_at
                  end) as oldestRunningStartedAt
            from ingestion_jobs
            """, nativeQuery = true)
    StatusSummaryRow summarizeStatus(@Param("before") Instant before);

    @Query("SELECT COUNT(j) FROM IngestionJob j WHERE j.status IN :statuses")
    long countByStatusIn(@Param("statuses") Collection<String> statuses);

    @Query("""
            select min(j.visibleAt)
            from IngestionJob j
            where j.status = :status
              and j.visibleAt <= :before
            """)
    Instant findOldestVisibleAtByStatusBefore(@Param("status") String status, @Param("before") Instant before);

    @Query("SELECT MIN(j.startedAt) FROM IngestionJob j WHERE j.status = :status")
    Instant findOldestStartedAtByStatus(@Param("status") String status);

    List<IngestionJob> findByStatus(String status);

    @Query("SELECT COUNT(j) FROM IngestionJob j WHERE j.requestedAt >= :since")
    long countAcceptedSince(@Param("since") Instant since);

    Page<IngestionJob> findAllByOrderByRequestedAtDescIdDesc(Pageable pageable);
}
