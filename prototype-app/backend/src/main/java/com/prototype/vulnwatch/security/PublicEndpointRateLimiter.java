package com.prototype.vulnwatch.security;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Locale;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class PublicEndpointRateLimiter {

    private final Cache<String, WindowCounter> counters = Caffeine.newBuilder()
            .maximumSize(100_000)
            .expireAfterAccess(Duration.ofHours(2))
            .build();
    private final boolean enabled;
    private final boolean trustProxyHeaders;

    public PublicEndpointRateLimiter(
            @Value("${app.security.public-rate-limit.enabled:true}") boolean enabled,
            @Value("${app.security.public-rate-limit.trust-proxy-headers:false}") boolean trustProxyHeaders
    ) {
        this.enabled = enabled;
        this.trustProxyHeaders = trustProxyHeaders;
    }

    public void checkRegistration(HttpServletRequest request, String email) {
        checkGlobal();
        check("registration:ip:" + clientIp(request), 10, Duration.ofMinutes(15));
        check("registration:email:" + fingerprint(email), 3, Duration.ofHours(1));
    }

    public void checkLogin(HttpServletRequest request, String email) {
        checkGlobal();
        check("login:ip:" + clientIp(request), 30, Duration.ofMinutes(15));
        check("login:email:" + fingerprint(email), 10, Duration.ofMinutes(15));
    }

    public void checkInvite(HttpServletRequest request, String token) {
        checkGlobal();
        check("invite:ip:" + clientIp(request), 60, Duration.ofMinutes(15));
        check("invite:token:" + fingerprint(token), 10, Duration.ofMinutes(15));
    }

    public void checkSetupSession(HttpServletRequest request, String token) {
        checkGlobal();
        check("setup-session:ip:" + clientIp(request), 20, Duration.ofMinutes(15));
        check("setup-session:token:" + fingerprint(token), 5, Duration.ofMinutes(15));
    }

    public void checkPasswordSetup(HttpServletRequest request, String sessionToken) {
        checkGlobal();
        check("setup-password:ip:" + clientIp(request), 20, Duration.ofMinutes(15));
        check("setup-password:session:" + fingerprint(sessionToken), 5, Duration.ofMinutes(15));
    }

    private void checkGlobal() {
        check("global", 300, Duration.ofMinutes(1));
    }

    private void check(String key, int limit, Duration window) {
        if (!enabled) {
            return;
        }
        long now = System.currentTimeMillis();
        WindowCounter counter = counters.get(key, ignored -> new WindowCounter(now + window.toMillis()));
        long retryAfterMillis;
        synchronized (counter) {
            if (now >= counter.resetAtMillis) {
                counter.count = 0;
                counter.resetAtMillis = now + window.toMillis();
            }
            counter.count++;
            if (counter.count <= limit) {
                return;
            }
            retryAfterMillis = counter.resetAtMillis - now;
        }
        throw new PublicRateLimitException((retryAfterMillis + 999) / 1000);
    }

    public String clientIp(HttpServletRequest request) {
        if (trustProxyHeaders) {
            String cloudflareIp = request.getHeader("CF-Connecting-IP");
            if (cloudflareIp != null && cloudflareIp.matches("[0-9a-fA-F:.]{2,64}")) {
                return cloudflareIp.toLowerCase(Locale.ROOT);
            }
        }
        String remoteAddress = request.getRemoteAddr();
        return remoteAddress == null || remoteAddress.isBlank() ? "unknown" : remoteAddress;
    }

    private String fingerprint(String value) {
        String normalized = value == null ? "missing" : value.trim().toLowerCase(Locale.ROOT);
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(normalized.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    private static final class WindowCounter {
        private int count;
        private long resetAtMillis;

        private WindowCounter(long resetAtMillis) {
            this.resetAtMillis = resetAtMillis;
        }
    }
}
