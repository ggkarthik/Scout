package com.prototype.vulnwatch.service;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.task.TaskExecutor;
import org.springframework.transaction.support.TransactionTemplate;

@ExtendWith(MockitoExtension.class)
class IngestionJobWorkerServiceTest {

    @Mock
    private IngestionJobService ingestionJobService;
    @Mock
    private IngestionJobExecutionService executionService;
    @Mock
    private IngestionJobLockService ingestionJobLockService;
    @Mock
    private TenantService tenantService;
    @Mock
    private TenantSchemaExecutionService tenantSchemaExecutionService;
    @Mock
    private TaskExecutor sbomJobExecutor;
    @Mock
    private TransactionTemplate transactionTemplate;

    private IngestionJobWorkerService service;

    @BeforeEach
    void setUp() {
        service = new IngestionJobWorkerService(
                ingestionJobService,
                executionService,
                ingestionJobLockService,
                tenantService,
                tenantSchemaExecutionService,
                sbomJobExecutor,
                transactionTemplate,
                10,
                1,
                5000
        );
    }

    @Test
    void pollJobsContinuesAfterOneTenantFails() {
        Tenant broken = tenant("broken");
        Tenant healthy = tenant("healthy");
        when(tenantService.listTenants()).thenReturn(List.of(broken, healthy));
        doThrow(new IllegalStateException("schema drift"))
                .when(ingestionJobService).claimPendingJobs(broken, 10, 1);

        UUID healthyTenantId = healthy.getId();
        UUID healthyJobId = UUID.randomUUID();
        when(ingestionJobService.claimPendingJobs(healthy, 10, 1))
                .thenReturn(List.of(new IngestionJobService.ClaimedJobRef(healthyTenantId, healthyJobId)));

        service.pollJobs();

        verify(ingestionJobService).claimPendingJobs(healthy, 10, 1);
        verify(sbomJobExecutor).execute(org.mockito.ArgumentMatchers.any(Runnable.class));
    }

    @Test
    void recoverInterruptedJobsDelegatesToService() {
        when(ingestionJobService.recoverInterruptedRunningJobs()).thenReturn(2);

        service.recoverInterruptedJobs();

        verify(ingestionJobService).recoverInterruptedRunningJobs();
        verify(sbomJobExecutor, never()).execute(org.mockito.ArgumentMatchers.any(Runnable.class));
    }

    private Tenant tenant(String slug) {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName(slug);
        tenant.setSchemaName("tenant_" + slug);
        return tenant;
    }
}
