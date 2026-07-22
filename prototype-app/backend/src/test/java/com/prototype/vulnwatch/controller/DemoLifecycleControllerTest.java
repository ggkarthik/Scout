package com.prototype.vulnwatch.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.service.DemoLifecycleService;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.WorkspaceService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class DemoLifecycleControllerTest {

    @AfterEach
    void tearDown() {
        TenantContext.clear();
    }

    @Test
    void inviteAcceptanceRunsInExplicitPreAuthenticationContext() {
        DemoLifecycleService lifecycleService = mock(DemoLifecycleService.class);
        when(lifecycleService.acceptInvite("invite-token")).thenAnswer(invocation -> {
            assertThat(TenantContext.isPreAuthenticationContext()).isTrue();
            assertThat(TenantContext.isPlatformContext()).isFalse();
            assertThat(TenantContext.getCurrentTenantId()).isNull();
            return null;
        });
        DemoLifecycleController controller = new DemoLifecycleController(
                lifecycleService,
                mock(RequestActorService.class),
                mock(WorkspaceService.class));

        controller.acceptInvite("invite-token");

        assertThat(TenantContext.isPreAuthenticationContext()).isFalse();
        assertThat(TenantContext.getCurrentTenantId()).isNull();
    }
}
