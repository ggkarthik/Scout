package com.prototype.vulnwatch.aisecurity.service;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.aisecurity.aws.AwsBedrockDiscoveryService.DiscoveryResult;
import com.prototype.vulnwatch.domain.IngestionJob;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.IngestionJobService;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantService;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.task.TaskExecutor;

@ExtendWith(MockitoExtension.class)
class AiSecurityJobWorkerServiceTest {

    @Mock private IngestionJobService jobs;
    @Mock private TenantService tenants;
    @Mock private TenantSchemaExecutionService tenantExecution;
    @Mock private AiSecurityDiscoveryProvider discovery;
    @Mock private TaskExecutor executor;

    private AiSecurityJobWorkerService worker;

    @BeforeEach
    void setUp() {
        when(discovery.jobType()).thenReturn(IngestionJobService.JOB_TYPE_AI_SECURITY_AWS_BEDROCK);
        worker = new AiSecurityJobWorkerService(
                jobs, tenants, tenantExecution, List.of(discovery), executor, true, 1);
    }

    @Test
    void pollContinuesWhenOneTenantCannotClaimJobs() {
        Tenant broken = tenant("broken");
        Tenant healthy = tenant("healthy");
        UUID jobId = UUID.randomUUID();
        when(discovery.provider()).thenReturn("AWS");
        when(tenants.listActiveTenants()).thenReturn(List.of(broken, healthy));
        doThrow(new IllegalStateException("schema unavailable"))
                .when(jobs).claimPendingJobsByType(
                        broken, IngestionJobService.JOB_TYPE_AI_SECURITY_AWS_BEDROCK, 1, 1);
        when(jobs.claimPendingJobsByType(
                healthy, IngestionJobService.JOB_TYPE_AI_SECURITY_AWS_BEDROCK, 1, 1))
                .thenReturn(List.of(new IngestionJobService.ClaimedJobRef(healthy.getId(), jobId)));

        worker.poll();

        verify(jobs).claimPendingJobsByType(
                healthy, IngestionJobService.JOB_TYPE_AI_SECURITY_AWS_BEDROCK, 1, 1);
        verify(executor).execute(any(Runnable.class));
    }

    @Test
    void executeCompletesOnlyTheClaimedTenantJob() {
        executeTenantCallbacks();
        Tenant tenant = tenant("healthy");
        UUID jobId = UUID.randomUUID();
        UUID connectorId = UUID.randomUUID();
        IngestionJob job = mock(IngestionJob.class);
        when(job.getJobType()).thenReturn(IngestionJobService.JOB_TYPE_AI_SECURITY_AWS_BEDROCK);
        when(tenants.resolveTenantUuid(tenant.getId())).thenReturn(tenant);
        when(jobs.loadJob(tenant.getId(), jobId)).thenReturn(job);
        when(jobs.readPayload(job, IngestionJobService.AiSecurityJobPayload.class))
                .thenReturn(new IngestionJobService.AiSecurityJobPayload(connectorId));
        DiscoveryResult result = new DiscoveryResult(UUID.randomUUID(), 4, 0);
        when(discovery.discover(tenant, connectorId)).thenReturn(result);
        when(jobs.toJson(result)).thenReturn("{\"artifactsObserved\":4}");

        worker.execute(tenant.getId(), jobId);

        verify(jobs).markSucceeded(
                tenant.getId(), jobId, null, "{\"artifactsObserved\":4}");
        verify(jobs, never()).markFailed(eq(tenant.getId()), eq(jobId), any(), any());
    }

    @Test
    void executeSanitizesProviderFailureWithinTheClaimedTenant() {
        executeTenantCallbacks();
        Tenant tenant = tenant("failing");
        UUID jobId = UUID.randomUUID();
        UUID connectorId = UUID.randomUUID();
        IngestionJob job = mock(IngestionJob.class);
        when(job.getJobType()).thenReturn(IngestionJobService.JOB_TYPE_AI_SECURITY_AWS_BEDROCK);
        when(tenants.resolveTenantUuid(tenant.getId())).thenReturn(tenant);
        when(jobs.loadJob(tenant.getId(), jobId)).thenReturn(job);
        when(jobs.readPayload(job, IngestionJobService.AiSecurityJobPayload.class))
                .thenReturn(new IngestionJobService.AiSecurityJobPayload(connectorId));
        when(discovery.discover(tenant, connectorId))
                .thenThrow(new IllegalStateException("secret provider response"));
        when(discovery.failureCode(any())).thenReturn("PROVIDER_UNAVAILABLE");
        when(discovery.safeFailureMessage("PROVIDER_UNAVAILABLE"))
                .thenReturn("AI Security discovery could not be completed");

        worker.execute(tenant.getId(), jobId);

        verify(jobs).markFailed(
                tenant.getId(),
                jobId,
                "PROVIDER_UNAVAILABLE",
                "AI Security discovery could not be completed");
        verify(jobs, never()).markSucceeded(eq(tenant.getId()), eq(jobId), any(), any());
    }

    private Tenant tenant(String slug) {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName(slug);
        tenant.setSchemaName("tenant_" + slug);
        return tenant;
    }

    private void executeTenantCallbacks() {
        doAnswer(invocation -> ((Supplier<?>) invocation.getArgument(1)).get())
                .when(tenantExecution).run(any(Tenant.class), any(Supplier.class));
    }
}
