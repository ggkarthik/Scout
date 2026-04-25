package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.FindingDeltaQueueEntry;
import java.time.Instant;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface FindingDeltaQueueEntryRepository extends JpaRepository<FindingDeltaQueueEntry, Long> {

    interface EventTypeCountRow {
        String getEventType();
        long getEntryCount();
    }

    /**
     * Atomically claim up to {@code limit} PENDING entries that are ready to process.
     * SKIP LOCKED ensures concurrent pollers never pick the same row.
     */
    @Query(value = """
            SELECT * FROM finding_delta_queue
             WHERE status = 'PENDING'
               AND visible_after <= now()
             ORDER BY id
             LIMIT :limit
             FOR UPDATE SKIP LOCKED
            """, nativeQuery = true)
    List<FindingDeltaQueueEntry> pollPending(@Param("limit") int limit);

    /**
     * Insert a new event, silently ignoring duplicates for the same dedupe_key
     * that are already PENDING. Returns 1 if inserted, 0 if skipped.
     */
    @Modifying
    @Transactional
    @Query(value = """
            INSERT INTO finding_delta_queue
                (event_type, tenant_id, component_id, vulnerability_id,
                 source_key, source_tag, dedupe_key)
            VALUES
                (:eventType, :tenantId, :componentId, :vulnerabilityId,
                 :sourceKey, :sourceTag, :dedupeKey)
            ON CONFLICT (dedupe_key) WHERE status = 'PENDING' DO NOTHING
            """, nativeQuery = true)
    int insertIfNotDuplicate(
            @Param("eventType")      String eventType,
            @Param("tenantId")       java.util.UUID tenantId,
            @Param("componentId")    java.util.UUID componentId,
            @Param("vulnerabilityId") java.util.UUID vulnerabilityId,
            @Param("sourceKey")      String sourceKey,
            @Param("sourceTag")      String sourceTag,
            @Param("dedupeKey")      String dedupeKey
    );

    @Query("SELECT COUNT(e) FROM FindingDeltaQueueEntry e WHERE e.status = 'PENDING'")
    long countPending();

    @Query("""
            select e.eventType as eventType, count(e) as entryCount
            from FindingDeltaQueueEntry e
            where e.status = 'PENDING'
            group by e.eventType
            """)
    List<EventTypeCountRow> countPendingByEventType();

    @Query("SELECT COUNT(e) FROM FindingDeltaQueueEntry e WHERE e.status = 'FAILED'")
    long countFailed();

    @Query("SELECT MAX(e.completedAt) FROM FindingDeltaQueueEntry e WHERE e.status = 'DONE'")
    Instant findLatestCompletedAt();

    /**
     * BLG-014: Count PENDING entries whose visible_after is before the given threshold —
     * i.e. items that should have been processed but have not been claimed yet.
     * Used by SloMetricsService to detect queue staleness.
     */
    @Query("SELECT COUNT(e) FROM FindingDeltaQueueEntry e WHERE e.status = 'PENDING' AND e.visibleAfter <= :threshold")
    long countStaleVisible(@Param("threshold") Instant threshold);
}
