package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

@ExtendWith(MockitoExtension.class)
class RequestActorServiceTest {

    @Mock
    private WorkspaceService workspaceService;

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void currentActorUsesWorkspaceContextAndCreatorRole() {
        Tenant tenant = tenant("Primary Workspace");
        when(workspaceService.getWorkspace()).thenReturn(tenant);

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                "analyst-1",
                "n/a",
                List.of(new SimpleGrantedAuthority("ROLE_CREATOR"), new SimpleGrantedAuthority("ROLE_OPERATOR"))
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);

        RequestActorService requestActorService = new RequestActorService(workspaceService, "fallback-user");
        RequestActor actor = requestActorService.currentActor();

        assertEquals("analyst-1", actor.userId());
        assertTrue(actor.creator());
        assertEquals(tenant.getId(), actor.tenantId());
        assertEquals("Primary Workspace", actor.tenantName());
    }

    @Test
    void currentActorFallsBackToConfiguredDefaultUserWhenAuthenticationMissing() {
        Tenant tenant = tenant("Primary Workspace");
        when(workspaceService.getWorkspace()).thenReturn(tenant);

        RequestActorService requestActorService = new RequestActorService(workspaceService, "local-analyst");
        RequestActor actor = requestActorService.currentActor();

        assertEquals("local-analyst", actor.userId());
        assertFalse(actor.creator());
        assertEquals(tenant.getId(), actor.tenantId());
        assertEquals("Primary Workspace", actor.tenantName());
    }

    private Tenant tenant(String name) {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName(name);
        return tenant;
    }
}
