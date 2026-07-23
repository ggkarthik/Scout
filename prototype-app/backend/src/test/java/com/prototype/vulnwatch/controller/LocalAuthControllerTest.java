package com.prototype.vulnwatch.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.dto.AuthSetupPasswordRequest;
import com.prototype.vulnwatch.dto.AuthTokenResponse;
import com.prototype.vulnwatch.service.LocalCredentialAuthService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.security.PasswordSetupCookieService;
import com.prototype.vulnwatch.security.PublicEndpointRateLimiter;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import java.time.Instant;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class LocalAuthControllerTest {

    @AfterEach
    void tearDown() {
        TenantContext.clear();
    }

    @Test
    void passwordSetupRunsInExplicitPreAuthenticationContext() {
        LocalCredentialAuthService authService = mock(LocalCredentialAuthService.class);
        AuthTokenResponse expected = new AuthTokenResponse("token", "Bearer", Instant.now().plusSeconds(300));
        when(authService.setupPassword("setup-token", "password-123")).thenAnswer(invocation -> {
            assertThat(TenantContext.isPreAuthenticationContext()).isTrue();
            assertThat(TenantContext.isPlatformContext()).isFalse();
            assertThat(TenantContext.getCurrentTenantId()).isNull();
            return expected;
        });
        LocalAuthController controller = new LocalAuthController(
                authService,
                mock(PasswordSetupCookieService.class),
                mock(PublicEndpointRateLimiter.class));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Scout-Setup", "1");
        AuthTokenResponse actual = controller.setupPassword(
                "setup-token",
                new AuthSetupPasswordRequest("password-123"),
                request,
                new MockHttpServletResponse());

        assertThat(actual).isSameAs(expected);
        assertThat(TenantContext.isPreAuthenticationContext()).isFalse();
    }
}
