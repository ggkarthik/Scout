package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.AuthTokenResponse;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AuthTokenService {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String LOCALHOST_FALLBACK_HMAC_SECRET = "localhost-dev-hmac-secret-32-bytes";

    private final String hmacSecret;
    private final long tokenTtlMinutes;
    private final String activeTenantIdClaim;
    private final boolean requireProductionSecrets;
    private final boolean sharedLocalhostLoginEnabled;
    private final String corsAllowedOrigins;

    @Autowired
    public AuthTokenService(
            @Value("${app.security.jwt.hmac-secret:}") String hmacSecret,
            @Value("${app.security.jwt.token-ttl-minutes:480}") long tokenTtlMinutes,
            @Value("${app.security.jwt.active-tenant-id-claim:active_tenant_id}") String activeTenantIdClaim,
            @Value("${app.security.require-production-secrets:false}") boolean requireProductionSecrets,
            @Value("${app.security.local-auth.shared-localhost-login-enabled:true}") boolean sharedLocalhostLoginEnabled,
            @Value("${app.cors.allowed-origins:}") String corsAllowedOrigins
    ) {
        this.hmacSecret = hmacSecret;
        this.tokenTtlMinutes = tokenTtlMinutes;
        this.activeTenantIdClaim = activeTenantIdClaim;
        this.requireProductionSecrets = requireProductionSecrets;
        this.sharedLocalhostLoginEnabled = sharedLocalhostLoginEnabled;
        this.corsAllowedOrigins = corsAllowedOrigins;
    }

    AuthTokenService(String hmacSecret, long tokenTtlMinutes, String activeTenantIdClaim) {
        this(
                hmacSecret,
                tokenTtlMinutes,
                activeTenantIdClaim,
                false,
                true,
                "http://localhost:5173,http://127.0.0.1:5173"
        );
    }

    public AuthTokenResponse issueToken(AppUser user, Set<String> roles, Tenant activeTenant) {
        requireIssuerConfigured();
        Instant now = Instant.now();
        Instant expiresAt = now.plus(Math.max(1, tokenTtlMinutes), ChronoUnit.MINUTES);
        return new AuthTokenResponse(
                signToken(user, roles, activeTenant, now, expiresAt),
                "Bearer",
                expiresAt);
    }

    private void requireIssuerConfigured() {
        if (resolvedHmacSecret().isBlank()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "APP_JWT_HMAC_SECRET is required for local credential login");
        }
    }

    private String signToken(AppUser user, Set<String> roles, Tenant activeTenant, Instant issuedAt, Instant expiresAt) {
        try {
            String header = json(Map.of("alg", "HS256", "typ", "JWT"));
            Map<String, Object> claims = new LinkedHashMap<>();
            claims.put("sub", user.getExternalSubject());
            if (user.getEmail() != null && !user.getEmail().isBlank()) {
                claims.put("email", user.getEmail());
            }
            if (user.getDisplayName() != null && !user.getDisplayName().isBlank()) {
                claims.put("name", user.getDisplayName());
            }
            claims.put("roles", roles);
            claims.put("iat", issuedAt.getEpochSecond());
            claims.put("exp", expiresAt.getEpochSecond());
            if (activeTenant != null) {
                claims.put(activeTenantIdClaim, activeTenant.getId().toString());
            }
            String unsigned = base64Url(header.getBytes(StandardCharsets.UTF_8))
                    + "."
                    + base64Url(json(claims).getBytes(StandardCharsets.UTF_8));
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(resolvedHmacSecret().getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return unsigned + "." + base64Url(mac.doFinal(unsigned.getBytes(StandardCharsets.UTF_8)));
        } catch (ResponseStatusException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to issue login token");
        }
    }

    private String json(Object value) throws Exception {
        return MAPPER.writeValueAsString(value);
    }

    private String base64Url(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private String resolvedHmacSecret() {
        if (hmacSecret != null && !hmacSecret.isBlank()) {
            return hmacSecret;
        }
        return isSharedLocalhostEnvironment() ? LOCALHOST_FALLBACK_HMAC_SECRET : "";
    }

    private boolean isSharedLocalhostEnvironment() {
        if (requireProductionSecrets || !sharedLocalhostLoginEnabled) {
            return false;
        }
        if (corsAllowedOrigins == null || corsAllowedOrigins.isBlank()) {
            return false;
        }
        return List.of(corsAllowedOrigins.split(",")).stream()
                .map(String::trim)
                .filter(origin -> !origin.isBlank())
                .allMatch(this::isLoopbackOrigin);
    }

    private boolean isLoopbackOrigin(String origin) {
        try {
            URI uri = URI.create(origin);
            return isLoopbackHost(uri.getHost());
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    private boolean isLoopbackHost(String host) {
        if (host == null || host.isBlank()) {
            return false;
        }
        String normalized = host.trim().toLowerCase(Locale.ROOT);
        return "localhost".equals(normalized)
                || "127.0.0.1".equals(normalized)
                || "::1".equals(normalized)
                || "[::1]".equals(normalized);
    }
}
