package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.IngestionJob;
import com.prototype.vulnwatch.domain.Tenant;
import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.RejectedExecutionException;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.task.TaskExecutor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class IngestionJobWorkerService {

    private final IngestionJobService ingestionJobService;
    private final IngestionJobExecutionService executionService;
    private final IngestionJobLockService ingestionJobLockService;
    private final TenantService tenantService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final TaskExecutor sbomJobExecutor;
    private final TransactionTemplate transactionTemplate;
    private final int pollBatchSize;
    private final int maxConcurrentPerTenant;
    private final long retryDelayMs;

    public IngestionJobWorkerService(
            IngestionJobService ingestionJobService,
            IngestionJobExecutionService executionService,
            IngestionJobLockService ingestionJobLockService,
            TenantService tenantService,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            @Qualifier("sbomJobExecutor") TaskExecutor sbomJobExecutor,
            TransactionTemplate transactionTemplate,
            @org.springframework.beans.factory.annotation.Value("${app.ingestion.jobs.poll-batch-size:10}") int pollBatchSize,
            @org.springframework.beans.factory.annotation.Value("${app.ingestion.jobs.max-concurrent-per-tenant:1}") int maxConcurrentPerTenant,
            @org.springframework.beans.factory.annotation.Value("${app.ingestion.jobs.retry-delay-ms:5000}") long retryDelayMs
    ) {
        this.ingestionJobService = ingestionJobService;
        this.executionService = executionService;
        this.ingestionJobLockService = ingestionJobLockService;
        this.tenantService = tenantService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.sbomJobExecutor = sbomJobExecutor;
        this.transactionTemplate = transactionTemplate;
        this.pollBatchSize = pollBatchSize;
        this.maxConcurrentPerTenant = maxConcurrentPerTenant;
        this.retryDelayMs = retryDelayMs;
    }

    @Scheduled(fixedDelayString = "${app.ingestion.jobs.poll-interval-ms:2000}")
    public void pollJobs() {
        for (Tenant tenant : tenantService.listTenants()) {
            List<IngestionJobService.ClaimedJobRef> claimed = ingestionJobService.claimPendingJobs(
                    tenant,
                    pollBatchSize,
                    maxConcurrentPerTenant
            );
            for (IngestionJobService.ClaimedJobRef ref : claimed) {
                try {
                    sbomJobExecutor.execute(() -> execute(ref.tenantId(), ref.jobId()));
                } catch (RejectedExecutionException ex) {
                    ingestionJobService.markQueuedForRetry(
                            ref.tenantId(),
                            ref.jobId(),
                            "EXECUTOR_BUSY",
                            "SBOM job executor is at capacity",
                            Instant.now().plusMillis(retryDelayMs)
                    );
                }
            }
        }
    }

    void execute(java.util.UUID tenantId, java.util.UUID jobId) {
        Tenant tenant = tenantService.resolveTenantUuid(tenantId);
        IngestionJob job = ingestionJobService.loadJob(tenantId, jobId);
        try {
            transactionTemplate.executeWithoutResult(status -> tenantSchemaExecutionService.run(tenant, () -> {
                IngestionJob activeJob = ingestionJobService.loadJob(tenantId, jobId);
                long lockKey = ingestionJobLockService.assetLockKey(tenantId, activeJob.getAssetIdentifier());
                boolean acquired = ingestionJobLockService.tryAcquireTransactionLock(lockKey);
                if (!acquired) {
                    ingestionJobService.recordLockRetry(activeJob);
                    ingestionJobService.markQueuedForRetry(
                            tenantId,
                            jobId,
                            "ASSET_LOCK_BUSY",
                            "Another ingestion is in progress for this asset",
                            Instant.now().plusMillis(retryDelayMs)
                    );
                    return null;
                }

                ingestionJobService.recordStarted(activeJob);
                IngestionJobExecutionService.ExecutionOutcome outcome;
                try {
                    outcome = executionService.execute(tenant, activeJob);
                } catch (IOException ex) {
                    throw new IllegalStateException(ex.getMessage(), ex);
                }
                ingestionJobService.markSucceeded(tenantId, jobId, outcome.sbomUpload(), outcome.resultJson());
                return null;
            }));
            IngestionJob completed = ingestionJobService.loadJob(tenantId, jobId);
            ingestionJobService.recordCompleted(completed);
        } catch (Exception ex) {
            IngestionJob failedJob = ingestionJobService.loadJob(tenantId, jobId);
            String message = ex.getMessage() == null ? "Failed to execute ingestion job" : ex.getMessage();
            ingestionJobService.markFailed(tenantId, jobId, failureCode(ex), message);
            ingestionJobService.recordFailed(ingestionJobService.loadJob(tenantId, jobId));
        }
    }

    private String failureCode(Exception ex) {
        if (ex instanceof IOException) {
            return "INGESTION_IO_FAILURE";
        }
        return "INGESTION_EXECUTION_FAILURE";
    }
}
