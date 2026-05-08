package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.config.TenantAuthenticationDetails;
import com.prototype.vulnwatch.domain.Tenant;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class WorkspaceServiceTest {

    @Mock
    private TenantService tenantService;

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

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

    @Test
    void rejectsPlatformOwnerJwtWithoutTenantContext() {
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                "owner@example.com",
                null);
        authentication.setDetails(new TenantAuthenticationDetails(
                null,
                null,
                "owner@example.com",
                java.util.Set.of("PLATFORM_OWNER")));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        WorkspaceService workspaceService = new WorkspaceService(tenantService, false);

        ResponseStatusException error = assertThrows(ResponseStatusException.class, workspaceService::getWorkspace);
        assertEquals(403, error.getStatusCode().value());
    }

    private Tenant tenant(String name) {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName(name);
        return tenant;
    }
}
