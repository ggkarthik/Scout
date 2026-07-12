package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.dto.AuthTokenResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

class AuthTokenServiceTest {

    @Test
    void localhostLoopbackConfigAllowsFallbackSecret() {
        AuthTokenService service = new AuthTokenService(
                "",
                60,
                "active_tenant_id",
                false,
                true,
                "http://localhost:5173,http://127.0.0.1:5173"
        );

        AuthTokenResponse response = service.issueToken(user("owner@example.com"), Set.of("PLATFORM_OWNER"), null);

        String[] parts = response.token().split("\\.");
        String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        assertEquals(3, parts.length);
        org.junit.jupiter.api.Assertions.assertTrue(payload.contains("\"sub\":\"owner@example.com\""));
    }

    @Test
    void nonLoopbackConfigStillRequiresExplicitSecret() {
        AuthTokenService service = new AuthTokenService(
                "",
                60,
                "active_tenant_id",
                false,
                true,
                "https://app.example.com"
        );

        ResponseStatusException error = assertThrows(
                ResponseStatusException.class,
                () -> service.issueToken(user("owner@example.com"), Set.of("PLATFORM_OWNER"), null)
        );

        assertEquals(HttpStatus.CONFLICT, error.getStatusCode());
        assertEquals("APP_JWT_HMAC_SECRET is required for local credential login", error.getReason());
    }

    @Test
    void productionModeStillRequiresExplicitSecret() {
        AuthTokenService service = new AuthTokenService(
                "",
                60,
                "active_tenant_id",
                true,
                true,
                "http://localhost:5173"
        );

        ResponseStatusException error = assertThrows(
                ResponseStatusException.class,
                () -> service.issueToken(user("owner@example.com"), Set.of("PLATFORM_OWNER"), null)
        );

        assertEquals(HttpStatus.CONFLICT, error.getStatusCode());
    }

    private AppUser user(String subject) {
        AppUser user = new AppUser();
        user.setExternalSubject(subject);
        user.setEmail(subject);
        user.setDisplayName("Test User");
        return user;
    }
}
