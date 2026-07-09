package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class FindingProjectionMaintenanceServiceTest {

    @Mock
    private TenantService tenantService;

    @Mock
    private FindingListProjectionService findingListProjectionService;

    private FindingProjectionMaintenanceService service;

    @BeforeEach
    void setUp() {
        service = new FindingProjectionMaintenanceService(tenantService, findingListProjectionService, 15);
    }

    @Test
    void refreshStaleProjectionsRefreshesMissingAndOldStatuses() {
        Tenant missingTenant = tenant("missing");
        Tenant staleTenant = tenant("stale");
        Tenant freshTenant = tenant("fresh");
        when(tenantService.listActiveTenants()).thenReturn(List.of(missingTenant, staleTenant, freshTenant));
        when(findingListProjectionService.inspectProjectionStatus(missingTenant))
                .thenReturn(FindingListProjectionService.ProjectionStatus.missing(10));
        when(findingListProjectionService.inspectProjectionStatus(staleTenant))
                .thenReturn(new FindingListProjectionService.ProjectionStatus(
                        Instant.now().minusSeconds(3600),
                        5,
                        5,
                        25L,
                        true,
                        0
                ));
        when(findingListProjectionService.inspectProjectionStatus(freshTenant))
                .thenReturn(new FindingListProjectionService.ProjectionStatus(
                        Instant.now(),
                        5,
                        5,
                        25L,
                        false,
                        0
                ));

        service.refreshStaleProjectionsOnStartup();

        verify(findingListProjectionService).refreshTenant(missingTenant);
        verify(findingListProjectionService).refreshTenant(staleTenant);
        verify(findingListProjectionService, never()).refreshTenant(freshTenant);
    }

    @Test
    void refreshStaleProjectionsOnScheduleDoesNotThrowWhenTenantLookupFails() {
        when(tenantService.listActiveTenants()).thenThrow(new IllegalStateException("db unavailable"));

        assertDoesNotThrow(() -> service.refreshStaleProjectionsOnSchedule());
    }

    @Test
    void refreshStaleProjectionsSkipsWhenRuntimeRoleIsApi() {
        service.setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy.forRole("api"));

        service.refreshStaleProjectionsOnStartup();

        verify(tenantService, never()).listActiveTenants();
    }

    private Tenant tenant(String name) {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName(name);
        tenant.setSchemaName("tenant_" + name);
        return tenant;
    }
}
