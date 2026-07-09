package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.IngestionJob;
import com.prototype.vulnwatch.domain.Tenant;
import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.RejectedExecutionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.task.TaskExecutor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class IngestionJobWorkerService {

    private static final Logger LOG = LoggerFactory.getLogger(IngestionJobWorkerService.class);

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
    private BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy = BackgroundTaskExecutionPolicy.allowAll();

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

    @org.springframework.beans.factory.annotation.Autowired
    public void setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy) {
        this.backgroundTaskExecutionPolicy = backgroundTaskExecutionPolicy == null
                ? BackgroundTaskExecutionPolicy.allowAll()
                : backgroundTaskExecutionPolicy;
    }

    @PostConstruct
    public void recoverInterruptedJobs() {
        if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("ingestion-job-worker.recover-interrupted-jobs")) {
            return;
        }
        int recovered = ingestionJobService.recoverInterruptedRunningJobs();
        if (recovered > 0) {
            LOG.warn("Recovered {} interrupted ingestion jobs left RUNNING during the previous process lifetime", recovered);
        }
    }

    @Scheduled(fixedDelayString = "${app.ingestion.jobs.poll-interval-ms:2000}")
    public void pollJobs() {
        if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("ingestion-job-worker.poll-jobs")) {
            return;
        }
        // This method MUST NOT let any exception escape. A periodic @Scheduled task that throws is
        // not rescheduled by Spring's ReschedulingRunnable, so a single transient failure (e.g. a DB
        // connection error after a host sleep/clock-leap exhausts the pool) would silently kill the
        // poller for the rest of the JVM's life and leave every ingestion job stuck in QUEUED. The
        // listActiveTenants() call below touches the database, so it has to be inside the guard too.
        try {
            TenantContext.runAsPlatform(() -> {
                for (Tenant tenant : tenantService.listActiveTenants()) {
                    try {
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
                    } catch (Exception ex) {
                        LOG.warn("Failed polling ingestion jobs for tenant {}: {}", tenant.getId(), ex.getMessage(), ex);
                    }
                }
            });
        } catch (Exception ex) {
            LOG.warn("Ingestion job poll cycle failed before tenant iteration: {}", ex.getMessage(), ex);
        }
    }

    void execute(java.util.UUID tenantId, java.util.UUID jobId) {
        Tenant tenant = tenantService.resolveTenantUuid(tenantId);
        IngestionJob job = ingestionJobService.loadJob(tenantId, jobId);
        try {
            // Tenant context first, transaction second: TenantAwareDataSource pins the connection's
            // search_path when the connection is acquired, so the transaction must begin *after* the
            // tenant schema is selected. Opening the transaction first would bind the default schema and
            // run the lock + ingestion against the wrong tenant.
            tenantSchemaExecutionService.run(tenant, () -> {
                transactionTemplate.executeWithoutResult(status -> {
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
                        return;
                    }

                    ingestionJobService.recordStarted(activeJob);
                    IngestionJobExecutionService.ExecutionOutcome outcome;
                    try {
                        outcome = executionService.execute(tenant, activeJob);
                    } catch (IOException ex) {
                        throw new IllegalStateException(ex.getMessage(), ex);
                    }
                    ingestionJobService.markSucceeded(tenantId, jobId, outcome.sbomUpload(), outcome.resultJson());
                });
                return null;
            });
            // Audit/metrics recording resolves the workspace from TenantContext, so it must run inside
            // the tenant scope too — otherwise it throws "Tenant context is required" on the worker thread
            // and a successful job is wrongly flipped to FAILED.
            tenantSchemaExecutionService.run(tenant, () -> {
                ingestionJobService.recordCompleted(ingestionJobService.loadJob(tenantId, jobId));
                return null;
            });
        } catch (Exception ex) {
            String message = ex.getMessage() == null ? "Failed to execute ingestion job" : ex.getMessage();
            tenantSchemaExecutionService.run(tenant, () -> {
                ingestionJobService.markFailed(tenantId, jobId, failureCode(ex), message);
                ingestionJobService.recordFailed(ingestionJobService.loadJob(tenantId, jobId));
                return null;
            });
        }
    }

    private String failureCode(Exception ex) {
        if (ex instanceof IOException) {
            return "INGESTION_IO_FAILURE";
        }
        return "INGESTION_EXECUTION_FAILURE";
    }
}
