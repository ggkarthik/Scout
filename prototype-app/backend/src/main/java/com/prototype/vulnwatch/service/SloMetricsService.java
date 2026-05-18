package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.SbomIngestionStatus;
import com.prototype.vulnwatch.dto.SloStatusResponse;
import com.prototype.vulnwatch.dto.SloStatusResponse.SloEntry;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * BLG-014: Evaluates platform SLOs against live repository data and returns a
 * structured snapshot of current compliance.
 *
 * SLOs are configurable via application properties so they can be tightened
 * (or relaxed) without a code change.
 */
@Service
public class SloMetricsService {

    private final JdbcTemplate platformJdbcTemplate;

    @Value("${app.slo.sbom-success-rate-min-pct:95.0}")
    private double sbomSuccessRateMinPct;

    @Value("${app.slo.queue-max-pending:100}")
    private long queueMaxPending;

    @Value("${app.slo.queue-stale-threshold-minutes:10}")
    private long queueStaleThresholdMinutes;

    @Value("${app.slo.queue-stale-max-count:0}")
    private long queueStaleMaxCount;

    public SloMetricsService(
            @Qualifier("platformJdbcTemplate") JdbcTemplate platformJdbcTemplate
    ) {
        this.platformJdbcTemplate = platformJdbcTemplate;
    }

    @Transactional(readOnly = true)
    public SloStatusResponse evaluate() {
        Instant now = Instant.now();
        List<SloEntry> entries = new ArrayList<>();

        // SLO-1: SBOM ingestion success rate (last 24 h)
        entries.add(evaluateSbomSuccessRate(now));

        // SLO-2: Delta queue depth — number of PENDING items must stay bounded
        entries.add(evaluateQueueDepth());

        // SLO-3: Delta queue staleness — no visible-but-unprocessed items older than threshold
        entries.add(evaluateQueueStaleness(now));

        boolean overallCompliant = entries.stream().allMatch(SloEntry::compliant);
        return new SloStatusResponse(now, overallCompliant, List.copyOf(entries));
    }

    // -------------------------------------------------------------------------

    private SloEntry evaluateSbomSuccessRate(Instant now) {
        Instant since = now.minus(24, ChronoUnit.HOURS);
        long total = countUploadsSince(since, null);
        long successes = countUploadsSince(since, SbomIngestionStatus.SUCCESS.name());

        double rate = total == 0 ? 100.0 : (successes * 100.0 / total);
        return new SloEntry(
                "sbom_ingestion_success_rate",
                "SBOM ingestion success rate over the last 24 hours",
                "%",
                sbomSuccessRateMinPct,
                round2(rate),
                rate >= sbomSuccessRateMinPct,
                "24h"
        );
    }

    private SloEntry evaluateQueueDepth() {
        long pending = queryCount(
                "select count(*) from finding_delta_queue where upper(status) = 'PENDING'"
        );
        return new SloEntry(
                "delta_queue_depth",
                "Number of PENDING finding delta events in the durable queue",
                "events",
                queueMaxPending,
                pending,
                pending <= queueMaxPending,
                "current"
        );
    }

    private SloEntry evaluateQueueStaleness(Instant now) {
        // A visible item that has not been claimed after the threshold window
        // indicates the poller is falling behind or has stalled.
        Instant staleThreshold = now.minus(queueStaleThresholdMinutes, ChronoUnit.MINUTES);
        long staleCount = queryCount(
                """
                select count(*)
                from finding_delta_queue
                where upper(status) = 'PENDING'
                  and visible_at <= ?
                """,
                java.sql.Timestamp.from(staleThreshold)
        );
        return new SloEntry(
                "delta_queue_stale_visible",
                "PENDING delta events that became visible more than " + queueStaleThresholdMinutes + " minutes ago",
                "events",
                queueStaleMaxCount,
                staleCount,
                staleCount <= queueStaleMaxCount,
                queueStaleThresholdMinutes + "m staleness window"
        );
    }

    private static double round2(double value) {
        return Math.round(value * 100.0) / 100.0;
    }

    private long countUploadsSince(Instant since, String status) {
        if (status == null) {
            return queryCount(
                    "select count(*) from sbom_uploads where uploaded_at >= ?",
                    java.sql.Timestamp.from(since)
            );
        }
        return queryCount(
                "select count(*) from sbom_uploads where uploaded_at >= ? and upper(status) = ?",
                java.sql.Timestamp.from(since),
                status.toUpperCase()
        );
    }

    private long queryCount(String sql, Object... args) {
        Long value = platformJdbcTemplate.queryForObject(sql, Long.class, args);
        return value == null ? 0L : value;
    }
}
