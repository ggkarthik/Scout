package com.prototype.vulnwatch.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletResponse;

class PasswordSetupCookieServiceTest {

    @Test
    void writesRestrictedNonCacheableSetupCookie() {
        MockHttpServletResponse response = new MockHttpServletResponse();

        new PasswordSetupCookieService(true, 30).write(response, "secret-token");

        String cookie = response.getHeader(HttpHeaders.SET_COOKIE);
        assertThat(cookie).contains("scout_setup_session=secret-token");
        assertThat(cookie).contains("Path=/api/auth");
        assertThat(cookie).contains("Secure");
        assertThat(cookie).contains("HttpOnly");
        assertThat(cookie).contains("SameSite=Strict");
        assertThat(response.getHeader(HttpHeaders.CACHE_CONTROL)).isEqualTo("no-store");
        assertThat(response.getHeader("Referrer-Policy")).isEqualTo("no-referrer");
    }
}
