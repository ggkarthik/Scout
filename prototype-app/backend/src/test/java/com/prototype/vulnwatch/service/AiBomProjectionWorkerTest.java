package com.prototype.vulnwatch.service;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.IngestionJob;
import com.prototype.vulnwatch.domain.Tenant;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/** Unit-level coverage of the throttle-vs-failure branching, without a database. */
@ExtendWith(MockitoExtension.class)
class AiBomProjectionWorkerTest {

    @Mock private IngestionJobService jobs;
    @Mock private TenantService tenants;
    @Mock private TenantSchemaExecutionService tenantExecution;
    @Mock private AiBomProjectionService projectionService;
    @Mock private AiBomProjectionSchedulingService schedulingService;

    private Tenant tenant;
    private UUID jobId;
    private UUID sourceId;
    private AiBomProjectionWorker worker;

    @BeforeEach
    void setUp() {
        lenient().doAnswer(invocation -> {
            ((Runnable) invocation.getArgument(1)).run();
            return null;
        }).when(tenantExecution).run(any(Tenant.class), any(Runnable.class));

        tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        jobId = UUID.randomUUID();
        sourceId = UUID.randomUUID();

        IngestionJob job = new IngestionJob();
        lenient().when(jobs.loadJob(tenant.getId(), jobId)).thenReturn(job);
        lenient().when(jobs.readPayload(job, IngestionJobService.AiGridBomProjectionJobPayload.class))
                .thenReturn(new IngestionJobService.AiGridBomProjectionJobPayload(sourceId));

        worker = new AiBomProjectionWorker(jobs, tenants, tenantExecution, projectionService, schedulingService, true);
    }

    private void process() {
        List<IngestionJobService.ClaimedJobRef> claimed =
                List.of(new IngestionJobService.ClaimedJobRef(tenant.getId(), jobId));
        when(jobs.claimPendingJobsByType(
                tenant, IngestionJobService.JOB_TYPE_AI_GRID_BOM_PROJECTION, 5, 5))
                .thenReturn(claimed);
        lenient().when(tenants.listActiveTenants()).thenReturn(List.of(tenant));

        worker.poll();
    }

    @Test
    void aThrottledExceptionRequeuesRatherThanFailingTheJob() {
        doThrow(new AiBomProjectionThrottledException("daily budget exhausted"))
                .when(projectionService).project(tenant, sourceId);

        process();

        verify(jobs).markQueuedForRetry(eq(tenant.getId()), eq(jobId), eq("DAILY_BUDGET_EXCEEDED"),
                anyString(), any(Instant.class));
        verify(jobs, never()).markFailed(any(), any(), any(), any());
        verify(jobs, never()).markSucceeded(any(), any(), any(), any());
        verify(jobs, never()).recordFailed(any());
        verify(jobs, never()).recordCompleted(any());
    }

    @Test
    void aGenericFailureStillMarksFailedNotQueuedForRetry() {
        doThrow(new IllegalStateException("boom")).when(projectionService).project(tenant, sourceId);

        process();

        verify(jobs).markFailed(eq(tenant.getId()), eq(jobId), eq("AI_BOM_PROJECTION_FAILED"), anyString());
        verify(jobs, never()).markQueuedForRetry(any(), any(), any(), any(), any());
    }

    @Test
    void successMarksSucceededAndNeverThrottles() {
        process();

        verify(jobs).markSucceeded(tenant.getId(), jobId, null, null);
        verify(jobs, never()).markQueuedForRetry(any(), any(), any(), any(), any());
        verify(jobs, never()).markFailed(any(), any(), any(), any());
    }

    @Test
    void reconcileDelegatesToTheSchedulingServiceForEveryActiveTenant() {
        when(tenants.listActiveTenants()).thenReturn(List.of(tenant));

        worker.reconcile();

        verify(schedulingService).reconcileHeldAndDeferredSources(tenant);
    }
}
