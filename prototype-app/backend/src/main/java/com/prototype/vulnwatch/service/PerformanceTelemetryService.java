package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * Registers queue and projection gauges that capture the freshness signals most likely to affect
 * analyst-perceived performance.
 */
@Service
public class PerformanceTelemetryService {
    private final MeterRegistry meterRegistry;
    private final TenantService tenantService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final FindingProjectionStatusService findingProjectionStatusService;
    private final JdbcTemplate jdbcTemplate;
    private final long staleProjectionThresholdSeconds;
    private final AtomicLong pendingQueueCount = new AtomicLong();
    private final AtomicLong oldestPendingAgeSeconds = new AtomicLong();
    private final AtomicLong staleProjectionTenantCount = new AtomicLong();
    private final AtomicLong maxProjectionLagSeconds = new AtomicLong();

    public PerformanceTelemetryService(
            ObjectProvider<MeterRegistry> meterRegistryProvider,
            TenantService tenantService,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            FindingProjectionStatusService findingProjectionStatusService,
            JdbcTemplate jdbcTemplate,
            @Value("${app.slo.projection-stale-threshold-minutes:15}") long projectionStaleThresholdMinutes
    ) {
        this.meterRegistry = meterRegistryProvider.getIfAvailable();
        this.tenantService = tenantService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.findingProjectionStatusService = findingProjectionStatusService;
        this.jdbcTemplate = jdbcTemplate;
        this.staleProjectionThresholdSeconds = projectionStaleThresholdMinutes * 60L;
        if (meterRegistry != null) {
            Gauge.builder("scoutgrid.finding_delta_queue.pending", pendingQueueCount, AtomicLong::doubleValue)
                    .description("Total PENDING entries across tenant finding delta queues.")
                    .register(meterRegistry);
            Gauge.builder("scoutgrid.finding_delta_queue.oldest_age_seconds", oldestPendingAgeSeconds, AtomicLong::doubleValue)
                    .description("Age in seconds of the oldest visible PENDING finding delta entry.")
                    .register(meterRegistry);
            Gauge.builder("scoutgrid.finding_projection.stale_tenants", staleProjectionTenantCount, AtomicLong::doubleValue)
                    .description("Tenants whose finding workspace projection is missing or stale.")
                    .register(meterRegistry);
            Gauge.builder("scoutgrid.finding_projection.max_lag_seconds", maxProjectionLagSeconds, AtomicLong::doubleValue)
                    .description("Maximum lag in seconds since any tenant last rebuilt the finding workspace projection.")
                    .register(meterRegistry);
        }
    }

    public void refreshFreshnessSnapshot() {
        if (meterRegistry == null) {
            return;
        }
        TenantContext.runAsPlatform(() -> {
            Instant now = Instant.now();
            long pendingCount = 0L;
            long maxOldestAgeSeconds = 0L;
            long staleTenants = 0L;
            long maxLagSeconds = 0L;

            for (Tenant tenant : tenantService.listTenants()) {
                TenantSnapshot snapshot = tenantSchemaExecutionService.run(tenant, () -> readTenantSnapshot(tenant, now));
                pendingCount += snapshot.pendingCount();
                maxOldestAgeSeconds = Math.max(maxOldestAgeSeconds, snapshot.oldestPendingAgeSeconds());
                staleTenants += snapshot.staleProjection() ? 1L : 0L;
                maxLagSeconds = Math.max(maxLagSeconds, snapshot.projectionLagSeconds());
            }

            pendingQueueCount.set(pendingCount);
            oldestPendingAgeSeconds.set(maxOldestAgeSeconds);
            staleProjectionTenantCount.set(staleTenants);
            maxProjectionLagSeconds.set(maxLagSeconds);
        });
    }

    private TenantSnapshot readTenantSnapshot(Tenant tenant, Instant now) {
        Long pendingCount = jdbcTemplate.queryForObject(
                "select count(*) from finding_delta_queue where upper(status) = 'PENDING'",
                Long.class
        );
        Timestamp oldestVisible = jdbcTemplate.query(
                """
                select min(visible_after)
                from finding_delta_queue
                where upper(status) = 'PENDING'
                  and visible_after <= now()
                """,
                rs -> rs.next() ? rs.getTimestamp(1) : null
        );
        long oldestAgeSeconds = 0L;
        if (oldestVisible != null) {
            oldestAgeSeconds = Math.max(0L, Duration.between(oldestVisible.toInstant(), now).getSeconds());
        }

        FindingListProjectionService.ProjectionStatus projectionStatus =
                findingProjectionStatusService.inspectProjectionStatus(tenant);
        long projectionLagSeconds = 0L;
        boolean staleProjection = true;
        if (projectionStatus != null && projectionStatus.lastComputedAt() != null) {
            projectionLagSeconds = Math.max(0L, Duration.between(projectionStatus.lastComputedAt(), now).getSeconds());
            staleProjection = projectionStatus.stale() || projectionLagSeconds > staleProjectionThresholdSeconds;
        }

        return new TenantSnapshot(
                pendingCount == null ? 0L : pendingCount,
                oldestAgeSeconds,
                staleProjection,
                projectionLagSeconds
        );
    }

    private record TenantSnapshot(
            long pendingCount,
            long oldestPendingAgeSeconds,
            boolean staleProjection,
            long projectionLagSeconds
    ) {
    }
}
