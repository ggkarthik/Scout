package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.repo.IngestionJobRepository;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tags;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Service;

@Service
public class IngestionJobMetricsService {

    private final MeterRegistry meterRegistry;
    private final TenantService tenantService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final IngestionJobRepository ingestionJobRepository;

    public IngestionJobMetricsService(
            ObjectProvider<MeterRegistry> meterRegistryProvider,
            TenantService tenantService,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            IngestionJobRepository ingestionJobRepository
    ) {
        this.meterRegistry = meterRegistryProvider.getIfAvailable();
        this.tenantService = tenantService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.ingestionJobRepository = ingestionJobRepository;
        registerGauges();
    }

    public void recordEnqueued(String sourceType) {
        increment("ingestion.jobs.enqueued", sourceType);
    }

    public void recordDeduped(String sourceType) {
        increment("ingestion.jobs.deduped", sourceType);
    }

    public void recordStarted(String sourceType) {
        increment("ingestion.jobs.started", sourceType);
    }

    public void recordEnqueueToStartLatency(String sourceType, Instant requestedAt, Instant startedAt) {
        if (meterRegistry == null || requestedAt == null || startedAt == null || startedAt.isBefore(requestedAt)) {
            return;
        }
        meterRegistry.timer("ingestion.jobs.enqueue_to_start.duration", Tags.of("sourceType", tagValue(sourceType)))
                .record(Duration.between(requestedAt, startedAt));
    }

    public void recordCompleted(String sourceType) {
        increment("ingestion.jobs.completed", sourceType);
    }

    public void recordFailed(String sourceType) {
        increment("ingestion.jobs.failed", sourceType);
    }

    public void recordLockRetry(String sourceType) {
        increment("ingestion.jobs.lock_retries", sourceType);
    }

    public void recordQuotaRejected(String sourceType) {
        increment("ingestion.jobs.quota_rejections", sourceType);
    }

    public void recordRateLimited(String sourceType) {
        increment("ingestion.jobs.rate_limit_rejections", sourceType);
    }

    public void recordAdmissionRejected(String sourceType) {
        increment("ingestion.jobs.admission_rejections", sourceType);
    }

    public void recordExecutionDuration(String sourceType, Instant startedAt, Instant completedAt) {
        if (meterRegistry == null || startedAt == null || completedAt == null || completedAt.isBefore(startedAt)) {
            return;
        }
        meterRegistry.timer("ingestion.jobs.execution.duration", Tags.of("sourceType", tagValue(sourceType)))
                .record(Duration.between(startedAt, completedAt));
    }

    private void increment(String name, String sourceType) {
        if (meterRegistry == null) {
            return;
        }
        meterRegistry.counter(name, "sourceType", tagValue(sourceType)).increment();
    }

    private void registerGauges() {
        if (meterRegistry == null) {
            return;
        }
        meterRegistry.gauge("ingestion.jobs.queue.depth", this, metrics -> metrics.countJobsWithStatuses(List.of("QUEUED")));
        meterRegistry.gauge("ingestion.jobs.active", this, metrics -> metrics.countJobsWithStatuses(List.of("QUEUED", "RUNNING")));
    }

    private double countJobsWithStatuses(List<String> statuses) {
        return tenantService.listTenants().stream()
                .mapToLong(tenant -> tenantSchemaExecutionService.run(tenant, () -> ingestionJobRepository.countByStatusIn(statuses)))
                .sum();
    }

    private String tagValue(String value) {
        return value == null || value.isBlank() ? "unknown" : value.trim().toLowerCase();
    }
}
