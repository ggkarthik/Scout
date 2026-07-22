package com.prototype.vulnwatch.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantUserInviteService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class TenantInviteControllerTest {

    @AfterEach
    void tearDown() {
        TenantContext.clear();
    }

    @Test
    void inviteAcceptanceRunsInExplicitPreAuthenticationContext() {
        TenantUserInviteService inviteService = mock(TenantUserInviteService.class);
        when(inviteService.acceptInvite("invite-token")).thenAnswer(invocation -> {
            assertThat(TenantContext.isPreAuthenticationContext()).isTrue();
            assertThat(TenantContext.isPlatformContext()).isFalse();
            assertThat(TenantContext.getCurrentTenantId()).isNull();
            return null;
        });
        TenantInviteController controller = new TenantInviteController(inviteService);

        controller.accept("invite-token");

        assertThat(TenantContext.isPreAuthenticationContext()).isFalse();
        assertThat(TenantContext.getCurrentTenantId()).isNull();
    }
}
