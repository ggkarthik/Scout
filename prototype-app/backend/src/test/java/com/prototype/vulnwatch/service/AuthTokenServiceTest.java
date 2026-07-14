package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.prototype.vulnwatch.domain.AppUser;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

class AuthTokenServiceTest {

    @Test
    void localhostLoopbackConfigStillRequiresExplicitSecret() {
        AuthTokenService service = new AuthTokenService(
                "",
                60,
                "active_tenant_id",
                false,
                true,
                "http://localhost:5173,http://127.0.0.1:5173"
        );

        ResponseStatusException error = assertThrows(
                ResponseStatusException.class,
                () -> service.issueToken(user("owner@example.com"), Set.of("PLATFORM_OWNER"), null)
        );
        assertEquals(HttpStatus.CONFLICT, error.getStatusCode());
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
