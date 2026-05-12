package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.AuthTokenResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AuthTokenService {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final String hmacSecret;
    private final long tokenTtlMinutes;
    private final String activeTenantIdClaim;

    public AuthTokenService(
            @Value("${app.security.jwt.hmac-secret:}") String hmacSecret,
            @Value("${app.security.jwt.token-ttl-minutes:480}") long tokenTtlMinutes,
            @Value("${app.security.jwt.active-tenant-id-claim:active_tenant_id}") String activeTenantIdClaim
    ) {
        this.hmacSecret = hmacSecret;
        this.tokenTtlMinutes = tokenTtlMinutes;
        this.activeTenantIdClaim = activeTenantIdClaim;
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
        if (hmacSecret == null || hmacSecret.isBlank()) {
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
            mac.init(new SecretKeySpec(hmacSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
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
}
