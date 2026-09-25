package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.IngestionJob;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.IngestionJobService;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantService;
import java.time.Instant;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/** Durable worker for admitted runtime adapter batches. */
@Service
public class AiGridRuntimeIngestionWorker {
    private final IngestionJobService jobs;
    private final TenantService tenants;
    private final TenantSchemaExecutionService tenantExecution;
    private final NamedParameterJdbcTemplate jdbc;
    private final AiAgentExecutionIngestionService ingestion;
    private final ObjectMapper mapper;
    private final boolean enabled;

    public AiGridRuntimeIngestionWorker(IngestionJobService jobs,
                                        TenantService tenants,
                                        TenantSchemaExecutionService tenantExecution,
                                        NamedParameterJdbcTemplate jdbc,
                                        AiAgentExecutionIngestionService ingestion,
                                        ObjectMapper mapper,
                                        @Value("${app.ai-security.runtime.adapter.worker-enabled:true}") boolean enabled) {
        this.jobs = jobs;
        this.tenants = tenants;
        this.tenantExecution = tenantExecution;
        this.jdbc = jdbc;
        this.ingestion = ingestion;
        this.mapper = mapper;
        this.enabled = enabled;
    }

    @Scheduled(fixedDelayString = "${app.ai-security.runtime.adapter.poll-interval-ms:2000}")
    public void poll() {
        if (!enabled) return;
        for (Tenant tenant : tenants.listActiveTenants()) {
            List<IngestionJobService.ClaimedJobRef> claimed = jobs.claimPendingJobsByType(
                    tenant, IngestionJobService.JOB_TYPE_AI_GRID_RUNTIME_ADAPTER, 1, 1);
            claimed.forEach(this::processSafely);
        }
    }

    private void processSafely(IngestionJobService.ClaimedJobRef ref) {
        IngestionJob job = jobs.loadJob(ref.tenantId(), ref.jobId());
        jobs.recordStarted(job);
        try {
            Tenant tenant = tenants.resolveTenantUuid(ref.tenantId());
            IngestionJobService.RuntimeAdapterJobPayload payload = jobs.readPayload(
                    job, IngestionJobService.RuntimeAdapterJobPayload.class);
            AiGridRuntimeIngestionService.RuntimeBatch batch = mapper.treeToValue(
                    payload.batch(), AiGridRuntimeIngestionService.RuntimeBatch.class);
            int accepted = 0;
            int duplicates = 0;
            int quarantined = 0;
            for (AiGridRuntimeIngestionService.RuntimeExecutionInput item : batch.executions()) {
                try {
                    AiAgentExecutionIngestionService.Result result = ingestion.ingest(tenant, null,
                            toExecution(payload.producerId(), batch, item));
                    if (result.duplicate()) duplicates++; else accepted++;
                } catch (IllegalArgumentException invalid) {
                    quarantined++;
                }
            }
            int finalAccepted = accepted;
            int finalDuplicates = duplicates;
            int finalQuarantined = quarantined;
            tenantExecution.run(tenant, () -> jdbc.update("""
                    update ai_runtime_ingestion_receipts set status='COMPLETED',accepted_count=:accepted,
                           duplicate_count=:duplicates,quarantined_count=:quarantined,
                           reason_code=:reason,completed_at=now()
                     where tenant_id=:tenantId and id=:receiptId
                    """, new MapSqlParameterSource().addValue("accepted", finalAccepted)
                    .addValue("duplicates", finalDuplicates).addValue("quarantined", finalQuarantined)
                    .addValue("reason", finalQuarantined > 0 ? "INVALID_RECORD_QUARANTINED" : null)
                    .addValue("tenantId", tenant.getId()).addValue("receiptId", payload.receiptId())));
            jobs.markSucceeded(ref.tenantId(), ref.jobId(), null, jobs.toJson(
                    new ProcessingResult(finalAccepted, finalDuplicates, finalQuarantined)));
            job.setCompletedAt(Instant.now());
            jobs.recordCompleted(job);
        } catch (Exception failure) {
            tenantExecution.run(ref.tenantId(), () -> jdbc.update("""
                    update ai_runtime_ingestion_receipts set status='FAILED',reason_code='PROCESSING_FAILED',completed_at=now()
                     where tenant_id=:tenantId and ingestion_job_id=:jobId
                    """, new MapSqlParameterSource().addValue("tenantId", ref.tenantId()).addValue("jobId", ref.jobId())));
            jobs.markFailed(ref.tenantId(), ref.jobId(), "RUNTIME_ADAPTER_PROCESSING_FAILED",
                    "Runtime adapter batch could not be processed");
            job.setCompletedAt(Instant.now());
            jobs.recordFailed(job);
        }
    }

    private AiAgentExecutionIngestionService.RuntimeExecution toExecution(
            String producerId, AiGridRuntimeIngestionService.RuntimeBatch batch,
            AiGridRuntimeIngestionService.RuntimeExecutionInput value) {
        return new AiAgentExecutionIngestionService.RuntimeExecution(
                batch.provider(), value.providerExecutionReference(), value.agentArtifactId(), producerId,
                value.scopeKey(), value.startedAt(), value.completedAt(), value.status(), value.outcomeCategory(),
                value.approvalState(), value.policyState(), value.classification(), value.apiVersion(), value.tokenCount(),
                value.latencyMs(), value.retryCount(), value.spendMicros(), value.eventTime(), value.events(),
                value.agentVersionArtifactId(), value.providerAgentReference(), value.providerAgentVersionReference(),
                value.correlationStatus(), value.correlationDiagnostic(), value.environmentReference(),
                value.deploymentReference(), value.actingIdentityReference(), value.delegatedIdentityReference(),
                value.terminationReason(), value.evidenceSource(), value.evidenceClass(), value.evidenceConfidence(),
                value.stepCount(), value.spendCurrency(), value.spendUnit(), value.collectedAt(),
                value.providerEventTime(), value.deliveryLatencyMs());
    }

    private record ProcessingResult(int acceptedCount, int duplicateCount, int quarantinedCount) { }
}
