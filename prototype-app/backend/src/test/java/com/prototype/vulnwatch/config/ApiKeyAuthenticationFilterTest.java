package com.prototype.vulnwatch.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

class ApiKeyAuthenticationFilterTest {

    @Test
    void skipsTheUnauthenticatedPasswordSetupSessionExchange() {
        ApiKeyAuthenticationFilter filter = new ApiKeyAuthenticationFilter(null, null);

        assertThat(filter.shouldNotFilter(new MockHttpServletRequest("POST", "/api/auth/setup-session")))
                .isTrue();
    }
}
