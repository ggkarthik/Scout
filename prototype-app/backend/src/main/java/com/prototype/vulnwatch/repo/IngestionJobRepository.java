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
             WHERE dedupe_key = :dedupeKey
               AND status IN ('QUEUED', 'RUNNING')
             ORDER BY requested_at DESC, id DESC
             LIMIT 1
             FOR UPDATE
            """, nativeQuery = true)
    Optional<IngestionJob> findActiveByDedupeKeyForUpdate(@Param("dedupeKey") String dedupeKey);

    @Query("SELECT COUNT(j) FROM IngestionJob j WHERE j.status = :status")
    long countByStatusValue(@Param("status") String status);

    @Query("SELECT COUNT(j) FROM IngestionJob j WHERE j.status IN :statuses")
    long countByStatusIn(@Param("statuses") Collection<String> statuses);

    @Query("SELECT COUNT(j) FROM IngestionJob j WHERE j.requestedAt >= :since")
    long countAcceptedSince(@Param("since") Instant since);

    Page<IngestionJob> findAllByOrderByRequestedAtDescIdDesc(Pageable pageable);
}
