package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.SbomIngestionStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.SloStatusResponse;
import com.prototype.vulnwatch.dto.SloStatusResponse.SloEntry;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * BLG-014: Evaluates platform SLOs against live repository data and returns a
 * structured snapshot of current compliance.
 *
 * SLOs are configurable via application properties so they can be tightened
 * (or relaxed) without a code change.
 */
@Service
public class SloMetricsService {

    private final JdbcTemplate jdbcTemplate;
    private final TenantService tenantService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final FindingProjectionStatusService findingProjectionStatusService;

    @Value("${app.slo.sbom-success-rate-min-pct:95.0}")
    private double sbomSuccessRateMinPct;

    @Value("${app.slo.queue-max-pending:100}")
    private long queueMaxPending;

    @Value("${app.slo.queue-stale-threshold-minutes:10}")
    private long queueStaleThresholdMinutes;

    @Value("${app.slo.queue-stale-max-count:0}")
    private long queueStaleMaxCount;

    @Value("${app.slo.queue-max-processing:100}")
    private long queueMaxProcessing;

    @Value("${app.slo.queue-processing-max-age-seconds:600}")
    private long queueProcessingMaxAgeSeconds;

    @Value("${app.slo.projection-stale-threshold-minutes:15}")
    private long projectionStaleThresholdMinutes;

    @Value("${app.slo.ingestion-queue-max-pending:25}")
    private long ingestionQueueMaxPending;

    @Value("${app.slo.ingestion-queue-max-age-seconds:600}")
    private long ingestionQueueMaxAgeSeconds;

    public SloMetricsService(
            JdbcTemplate jdbcTemplate,
            TenantService tenantService,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            FindingProjectionStatusService findingProjectionStatusService
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.tenantService = tenantService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.findingProjectionStatusService = findingProjectionStatusService;
    }

    public SloStatusResponse evaluate() {
        return TenantContext.runAsPlatform(() -> {
            Instant now = Instant.now();
            List<SloEntry> entries = new ArrayList<>();

            // SLO-1: SBOM ingestion success rate (last 24 h)
            entries.add(evaluateSbomSuccessRate(now));

            // SLO-2: Delta queue depth — number of PENDING items must stay bounded
            entries.add(evaluateQueueDepth());

            // SLO-3: Delta queue staleness — no visible-but-unprocessed items older than threshold
            entries.add(evaluateQueueStaleness(now));

            // SLO-4: Finding workspace projection freshness
            entries.add(evaluateProjectionFreshness(now));

            // SLO-5: Delta queue processing depth — in-flight work must stay bounded
            entries.add(evaluateProcessingDepth());

            // SLO-6: Delta queue processing age — processing work must continue making progress
            entries.add(evaluateProcessingAge(now));

            // SLO-7: Ingestion queue depth — queued ingestion work must stay bounded
            entries.add(evaluateIngestionQueueDepth());

            // SLO-8: Ingestion queue age — queued ingestion work must not sit unclaimed too long
            entries.add(evaluateIngestionQueueAge(now));

            boolean overallCompliant = entries.stream().allMatch(SloEntry::compliant);
            return new SloStatusResponse(now, overallCompliant, List.copyOf(entries));
        });
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

    private static double round2(double value) {
        return Math.round(value * 100.0) / 100.0;
    }

    private long countUploadsSince(Instant since, String status) {
        return sumAcrossTenants(tenant -> {
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
        });
    }

    private long queryCount(String sql, Object... args) {
        Long value = jdbcTemplate.queryForObject(sql, Long.class, args);
        return value == null ? 0L : value;
    }

    private long sumAcrossTenants(java.util.function.Function<Tenant, Long> aggregator) {
        long total = 0L;
        for (Tenant tenant : tenantService.listTenants()) {
            total += tenantSchemaExecutionService.run(tenant, () -> {
                Long value = aggregator.apply(tenant);
                return value == null ? 0L : value;
            });
        }
        return total;
    }

    private SloEntry evaluateQueueDepth() {
        long pending = sumAcrossTenants(tenant ->
                queryCount("select count(*) from finding_delta_queue where upper(status) = 'PENDING'")
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
        Instant staleThreshold = now.minus(queueStaleThresholdMinutes, ChronoUnit.MINUTES);
        long staleCount = sumAcrossTenants(tenant ->
                queryCount(
                        """
                        select count(*)
                        from finding_delta_queue
                        where upper(status) = 'PENDING'
                          and visible_after <= ?
                        """,
                        java.sql.Timestamp.from(staleThreshold)
                )
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

    private SloEntry evaluateProjectionFreshness(Instant now) {
        long staleCount = 0L;
        for (Tenant tenant : tenantService.listTenants()) {
            FindingListProjectionService.ProjectionStatus status = findingProjectionStatusService.inspectProjectionStatus(tenant);
            if (status == null || status.missing() || status.stale() || status.driftCount() != 0L) {
                staleCount += 1L;
            }
        }
        return new SloEntry(
                "finding_projection_freshness",
                "Tenants whose finding workspace projection is missing or older than "
                        + projectionStaleThresholdMinutes + " minutes",
                "tenants",
                0L,
                staleCount,
                staleCount == 0L,
                projectionStaleThresholdMinutes + "m freshness window"
        );
    }

    private SloEntry evaluateProcessingDepth() {
        long processing = sumAcrossTenants(tenant ->
                queryCount("select count(*) from finding_delta_queue where upper(status) = 'PROCESSING'")
        );
        return new SloEntry(
                "delta_queue_processing_depth",
                "Number of PROCESSING finding delta events currently in-flight",
                "events",
                queueMaxProcessing,
                processing,
                processing <= queueMaxProcessing,
                "current"
        );
    }

    private SloEntry evaluateProcessingAge(Instant now) {
        long oldestAgeSeconds = maxAcrossTenants(tenant -> {
            Instant startedAt = queryInstant(
                    """
                    select min(processing_started_at)
                    from finding_delta_queue
                    where upper(status) = 'PROCESSING'
                    """
            );
            return ageSeconds(startedAt, now);
        });
        return new SloEntry(
                "delta_queue_processing_oldest_age",
                "Age in seconds of the oldest PROCESSING finding delta event",
                "seconds",
                queueProcessingMaxAgeSeconds,
                oldestAgeSeconds,
                oldestAgeSeconds <= queueProcessingMaxAgeSeconds,
                "current"
        );
    }

    private SloEntry evaluateIngestionQueueDepth() {
        long queued = sumAcrossTenants(tenant ->
                queryCount("select count(*) from ingestion_jobs where upper(status) = 'QUEUED'")
        );
        return new SloEntry(
                "ingestion_queue_depth",
                "Number of QUEUED ingestion jobs awaiting workers",
                "jobs",
                ingestionQueueMaxPending,
                queued,
                queued <= ingestionQueueMaxPending,
                "current"
        );
    }

    private SloEntry evaluateIngestionQueueAge(Instant now) {
        long oldestAgeSeconds = maxAcrossTenants(tenant -> {
            Instant visibleAt = queryInstant(
                    """
                    select min(visible_at)
                    from ingestion_jobs
                    where upper(status) = 'QUEUED'
                      and visible_at <= ?
                    """,
                    java.sql.Timestamp.from(now)
            );
            return ageSeconds(visibleAt, now);
        });
        return new SloEntry(
                "ingestion_queue_oldest_age",
                "Age in seconds of the oldest visible QUEUED ingestion job",
                "seconds",
                ingestionQueueMaxAgeSeconds,
                oldestAgeSeconds,
                oldestAgeSeconds <= ingestionQueueMaxAgeSeconds,
                "current"
        );
    }

    private Instant queryInstant(String sql, Object... args) {
        java.sql.Timestamp value = jdbcTemplate.queryForObject(sql, java.sql.Timestamp.class, args);
        return value == null ? null : value.toInstant();
    }

    private long maxAcrossTenants(java.util.function.Function<Tenant, Long> aggregator) {
        long max = 0L;
        for (Tenant tenant : tenantService.listTenants()) {
            long value = tenantSchemaExecutionService.run(tenant, () -> {
                Long result = aggregator.apply(tenant);
                return result == null ? 0L : result;
            });
            max = Math.max(max, value);
        }
        return max;
    }

    private long ageSeconds(Instant startedAt, Instant now) {
        if (startedAt == null || now == null || startedAt.isAfter(now)) {
            return 0L;
        }
        return Math.max(0L, java.time.Duration.between(startedAt, now).getSeconds());
    }
}
