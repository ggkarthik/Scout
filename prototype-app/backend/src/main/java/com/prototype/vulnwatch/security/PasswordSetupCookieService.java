package com.prototype.vulnwatch.security;

import jakarta.servlet.http.HttpServletResponse;
import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
public class PasswordSetupCookieService {

    public static final String COOKIE_NAME = "scout_setup_session";
    private static final String COOKIE_PATH = "/api/auth";

    private final boolean secure;
    private final Duration ttl;

    public PasswordSetupCookieService(
            @Value("${app.security.local-auth.setup-cookie-secure:false}") boolean secure,
            @Value("${app.security.local-auth.setup-token-ttl-minutes:30}") long ttlMinutes
    ) {
        this.secure = secure;
        this.ttl = Duration.ofMinutes(Math.max(5, Math.min(ttlMinutes, 60)));
    }

    public void write(HttpServletResponse response, String token) {
        if (token == null || token.isBlank()) {
            return;
        }
        response.addHeader(HttpHeaders.SET_COOKIE, cookie(token, ttl).toString());
        noStore(response);
    }

    public void clear(HttpServletResponse response) {
        response.addHeader(HttpHeaders.SET_COOKIE, cookie("", Duration.ZERO).toString());
        noStore(response);
    }

    public void noStore(HttpServletResponse response) {
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.setHeader(HttpHeaders.PRAGMA, "no-cache");
        response.setHeader("Referrer-Policy", "no-referrer");
    }

    private ResponseCookie cookie(String value, Duration maxAge) {
        return ResponseCookie.from(COOKIE_NAME, value)
                .httpOnly(true)
                .secure(secure)
                .sameSite("Strict")
                .path(COOKIE_PATH)
                .maxAge(maxAge)
                .build();
    }
}
