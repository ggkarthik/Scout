package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class WorkspaceServiceTest {

    @Mock
    private TenantService tenantService;

    @Test
    void cachesWorkspaceAfterFirstResolution() {
        Tenant tenant = tenant("Primary Workspace");
        when(tenantService.getDefaultTenant()).thenReturn(tenant);

        WorkspaceService workspaceService = new WorkspaceService(tenantService, false);

        Tenant first = workspaceService.getWorkspace();
        Tenant second = workspaceService.getWorkspace();

        assertSame(tenant, first);
        assertSame(tenant, second);
        assertEquals(tenant.getId(), workspaceService.getWorkspaceId());
        verify(tenantService, times(1)).getDefaultTenant();
    }

    @Test
    void refreshWorkspaceReplacesCachedWorkspace() {
        Tenant initial = tenant("Workspace A");
        Tenant refreshed = tenant("Workspace B");
        when(tenantService.getDefaultTenant()).thenReturn(initial, refreshed);

        WorkspaceService workspaceService = new WorkspaceService(tenantService, false);

        assertSame(initial, workspaceService.getWorkspace());
        assertSame(refreshed, workspaceService.refreshWorkspace());
        assertSame(refreshed, workspaceService.getWorkspace());
        verify(tenantService, times(2)).getDefaultTenant();
    }

    private Tenant tenant(String name) {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName(name);
        return tenant;
    }
}
