package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.SbomIngestionStatus;
import com.prototype.vulnwatch.dto.SloStatusResponse;
import com.prototype.vulnwatch.dto.SloStatusResponse.SloEntry;
import com.prototype.vulnwatch.repo.FindingDeltaQueueEntryRepository;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
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

    private final SbomUploadRepository sbomUploadRepository;
    private final FindingDeltaQueueEntryRepository deltaQueueRepository;

    @Value("${app.slo.sbom-success-rate-min-pct:95.0}")
    private double sbomSuccessRateMinPct;

    @Value("${app.slo.queue-max-pending:100}")
    private long queueMaxPending;

    @Value("${app.slo.queue-stale-threshold-minutes:10}")
    private long queueStaleThresholdMinutes;

    @Value("${app.slo.queue-stale-max-count:0}")
    private long queueStaleMaxCount;

    public SloMetricsService(
            SbomUploadRepository sbomUploadRepository,
            FindingDeltaQueueEntryRepository deltaQueueRepository
    ) {
        this.sbomUploadRepository = sbomUploadRepository;
        this.deltaQueueRepository = deltaQueueRepository;
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
        var uploads = sbomUploadRepository
                .findByTenantAndUploadedAtGreaterThanEqualOrderByUploadedAtDesc(null, since);

        // findByTenantAndUploadedAt with null tenant returns all tenants via the
        // default tenant path; fall back to all uploads if that returns empty.
        var allUploads = uploads.isEmpty()
                ? sbomUploadRepository.findAll().stream()
                        .filter(u -> u.getUploadedAt() != null && !u.getUploadedAt().isBefore(since))
                        .toList()
                : uploads;

        long total = allUploads.size();
        long successes = allUploads.stream()
                .filter(u -> SbomIngestionStatus.SUCCESS == u.getStatus())
                .count();

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
        long pending = deltaQueueRepository.countPending();
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
        long staleCount = deltaQueueRepository.countStaleVisible(staleThreshold);
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
}
