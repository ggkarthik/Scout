package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.aisecurity.aws.AwsBedrockDiscoveryService;
import com.prototype.vulnwatch.domain.IngestionJob;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.BackgroundTaskExecutionPolicy;
import com.prototype.vulnwatch.service.IngestionJobService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantService;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicInteger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.task.TaskExecutor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Service
public class AiSecurityJobWorkerService {

    private static final Logger LOG = LoggerFactory.getLogger(AiSecurityJobWorkerService.class);

    private final IngestionJobService jobs;
    private final TenantService tenants;
    private final TenantSchemaExecutionService tenantExecution;
    private final AwsBedrockDiscoveryService discoveryService;
    private final TaskExecutor executor;
    private final boolean enabled;
    private final int maxConcurrentPerTenant;
    private final AtomicInteger tenantCursor = new AtomicInteger();
    private BackgroundTaskExecutionPolicy backgroundPolicy = BackgroundTaskExecutionPolicy.allowAll();

    public AiSecurityJobWorkerService(
            IngestionJobService jobs,
            TenantService tenants,
            TenantSchemaExecutionService tenantExecution,
            AwsBedrockDiscoveryService discoveryService,
            @Qualifier("aiSecurityJobExecutor") TaskExecutor executor,
            @Value("${app.ai-security.jobs.enabled:true}") boolean enabled,
            @Value("${app.ai-security.jobs.max-concurrent-per-tenant:1}") int maxConcurrentPerTenant
    ) {
        this.jobs = jobs;
        this.tenants = tenants;
        this.tenantExecution = tenantExecution;
        this.discoveryService = discoveryService;
        this.executor = executor;
        this.enabled = enabled;
        this.maxConcurrentPerTenant = Math.max(1, maxConcurrentPerTenant);
    }

    @org.springframework.beans.factory.annotation.Autowired
    void setBackgroundPolicy(BackgroundTaskExecutionPolicy backgroundPolicy) {
        this.backgroundPolicy = backgroundPolicy == null ? BackgroundTaskExecutionPolicy.allowAll() : backgroundPolicy;
    }

    @Scheduled(fixedDelayString = "${app.ai-security.jobs.poll-interval-ms:3000}")
    public void poll() {
        if (!enabled || !backgroundPolicy.allowsBackgroundTask("ai-security-job-worker.poll")) {
            return;
        }
        try {
            TenantContext.runAsPlatform(() -> {
                List<Tenant> active = new ArrayList<>(tenants.listActiveTenants());
                if (active.isEmpty()) {
                    return null;
                }
                Collections.rotate(active, -(Math.floorMod(tenantCursor.getAndIncrement(), active.size())));
                for (Tenant tenant : active) {
                    try {
                        List<IngestionJobService.ClaimedJobRef> claimed = jobs.claimPendingJobsByType(
                                tenant,
                                IngestionJobService.JOB_TYPE_AI_SECURITY_AWS_BEDROCK,
                                1,
                                maxConcurrentPerTenant);
                        for (var ref : claimed) {
                            try {
                                executor.execute(() -> execute(ref.tenantId(), ref.jobId()));
                            } catch (RejectedExecutionException ex) {
                                jobs.markQueuedForRetry(
                                        ref.tenantId(), ref.jobId(), "EXECUTOR_BUSY",
                                        "AI Security worker is at capacity", Instant.now().plusSeconds(5));
                            }
                        }
                    } catch (Exception ex) {
                        LOG.warn("AI Security job claim failed for tenant {}: {}", tenant.getId(), ex.getMessage());
                    }
                }
                return null;
            });
        } catch (Exception ex) {
            LOG.warn("AI Security job poll failed: {}", ex.getMessage());
        }
    }

    void execute(java.util.UUID tenantId, java.util.UUID jobId) {
        Tenant tenant = tenants.resolveTenantUuid(tenantId);
        try {
            tenantExecution.run(tenant, () -> {
                IngestionJob job = jobs.loadJob(tenantId, jobId);
                jobs.recordStarted(job);
                IngestionJobService.AiSecurityJobPayload payload =
                        jobs.readPayload(job, IngestionJobService.AiSecurityJobPayload.class);
                var result = discoveryService.discover(tenant, payload.connectorId());
                jobs.markSucceeded(tenantId, jobId, null, jobs.toJson(result));
                jobs.recordCompleted(jobs.loadJob(tenantId, jobId));
                return null;
            });
        } catch (Exception ex) {
            tenantExecution.run(tenant, () -> {
                jobs.markFailed(tenantId, jobId, failureCode(ex), safeMessage(ex));
                jobs.recordFailed(jobs.loadJob(tenantId, jobId));
                return null;
            });
        }
    }

    private String failureCode(Exception ex) {
        if (ex instanceof software.amazon.awssdk.services.sts.model.StsException) {
            return "ASSUME_ROLE_FAILED";
        }
        if (ex instanceof software.amazon.awssdk.core.exception.SdkServiceException sdk && sdk.statusCode() == 429) {
            return "THROTTLED";
        }
        if (ex instanceof com.prototype.vulnwatch.aisecurity.aws.AiSecurityAwsAdmissionService.AdmissionException) {
            return "THROTTLED";
        }
        return "PROVIDER_UNAVAILABLE";
    }

    private String safeMessage(Exception ex) {
        return switch (failureCode(ex)) {
            case "ASSUME_ROLE_FAILED" -> "Unable to assume the configured AWS role";
            case "THROTTLED" -> "AWS temporarily throttled the AI Security scan";
            default -> "AI Security discovery could not be completed";
        };
    }
}
