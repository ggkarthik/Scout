package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.IngestionJob;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.IngestionJobService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantSchemaService;
import com.prototype.vulnwatch.service.TenantService;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

class AiGridRuntimeIngestionWorkerTest {
    @AfterEach
    void clearContext() {
        TenantContext.clear();
    }

    @Test
    void auditFailureIsTenantScopedAndTerminatesClaimedJob() {
        UUID tenantId = UUID.randomUUID();
        UUID jobId = UUID.randomUUID();
        Tenant tenant = new Tenant();
        tenant.setId(tenantId);
        tenant.setSchemaName("tenant_pilot");
        TenantService tenants = mock(TenantService.class);
        TenantSchemaService schemas = mock(TenantSchemaService.class);
        when(tenants.listActiveTenants()).thenReturn(List.of(tenant));
        when(tenants.resolveTenantUuid(tenantId)).thenReturn(tenant);
        when(schemas.schemaNameForTenant(tenant)).thenReturn("tenant_pilot");
        TenantSchemaExecutionService scope = new TenantSchemaExecutionService(tenants, schemas, "ENFORCE");
        IngestionJobService jobs = mock(IngestionJobService.class);
        IngestionJob job = mock(IngestionJob.class);
        when(job.getId()).thenReturn(jobId);
        when(jobs.claimPendingJobsByType(tenant, IngestionJobService.JOB_TYPE_AI_GRID_RUNTIME_ADAPTER, 1, 1))
                .thenReturn(List.of(new IngestionJobService.ClaimedJobRef(tenantId, jobId)));
        when(jobs.loadJob(tenantId, jobId)).thenReturn(job);
        doAnswer(invocation -> {
            assertEquals(tenantId, TenantContext.getCurrentTenantId());
            assertEquals("tenant_pilot", TenantContext.getCurrentSchemaName());
            throw new IllegalStateException("Audit storage unavailable");
        }).when(jobs).recordStarted(job);
        doAnswer(invocation -> {
            assertEquals(tenantId, TenantContext.getCurrentTenantId());
            return null;
        }).when(jobs).markFailed(eq(tenantId), eq(jobId), any(), any());
        AiGridRuntimeIngestionWorker worker = new AiGridRuntimeIngestionWorker(jobs, tenants, scope,
                mock(NamedParameterJdbcTemplate.class), mock(AiAgentExecutionIngestionService.class),
                new ObjectMapper(), true);

        worker.poll();

        verify(jobs).markFailed(tenantId, jobId, "RUNTIME_ADAPTER_PROCESSING_FAILED",
                "Runtime adapter batch could not be processed");
        verify(jobs).recordFailed(job);
        assertNull(TenantContext.getCurrentTenantId());
    }
}
