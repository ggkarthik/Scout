package com.prototype.vulnwatch.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantMembership;
import com.prototype.vulnwatch.dto.AuthSessionResponse;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class ValidationAuthService {

    private final AppUserRepository appUserRepository;
    private final TenantMembershipRepository membershipRepository;
    private final PasswordEncoder passwordEncoder;
    private final byte[] hmacSecret;
    private final long sessionTtlHours;

    public ValidationAuthService(
            AppUserRepository appUserRepository,
            TenantMembershipRepository membershipRepository,
            PasswordEncoder passwordEncoder,
            @Value("${app.security.jwt.hmac-secret:}") String hmacSecret,
            @Value("${app.auth.session-ttl-hours:12}") long sessionTtlHours
    ) {
        this.appUserRepository = appUserRepository;
        this.membershipRepository = membershipRepository;
        this.passwordEncoder = passwordEncoder;
        this.hmacSecret = hmacSecret == null ? new byte[0] : hmacSecret.getBytes(StandardCharsets.UTF_8);
        this.sessionTtlHours = sessionTtlHours <= 0 ? 12 : sessionTtlHours;
    }

    @Transactional(readOnly = true)
    public AuthSessionResponse login(String email, String password) {
        String normalizedEmail = normalizeEmail(email);
        AppUser user = appUserRepository.findByEmailIgnoreCase(normalizedEmail)
                .orElseThrow(this::invalidCredentials);
        if (!"ACTIVE".equalsIgnoreCase(user.getStatus())) {
            throw invalidCredentials();
        }
        if (user.getPasswordHash() == null || user.getPasswordHash().isBlank()
                || !passwordEncoder.matches(password, user.getPasswordHash())) {
            throw invalidCredentials();
        }
        return issueSession(user);
    }

    @Transactional
    public AuthSessionResponse setPasswordAndIssueSession(AppUser user, String password) {
        if (user == null) {
            throw invalidCredentials();
        }
        user.setPasswordHash(passwordEncoder.encode(requirePassword(password)));
        user.setPasswordSetAt(Instant.now());
        user.setStatus("ACTIVE");
        user.setUpdatedAt(Instant.now());
        appUserRepository.save(user);
        return issueSession(user);
    }

    public AuthSessionResponse issueSession(AppUser user) {
        requireHmacSecret();
        Tenant tenant = null;
        Set<String> roles = new LinkedHashSet<>();
        if (user.isPlatformOwner()) {
            roles.add("PLATFORM_OWNER");
        }
        List<TenantMembership> memberships = membershipRepository
                .findByUserExternalSubjectAndStatusOrderByCreatedAtAsc(user.getExternalSubject(), "ACTIVE");
        if (!memberships.isEmpty()) {
            TenantMembership membership = memberships.get(0);
            tenant = membership.getTenant();
            roles.add(membership.getRole());
        }
        if (tenant == null && roles.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "User does not have an active workspace");
        }
        return signToken(user, tenant, roles);
    }

    private AuthSessionResponse signToken(AppUser user, Tenant tenant, Set<String> roles) {
        Instant now = Instant.now();
        Instant expiresAt = now.plus(sessionTtlHours, ChronoUnit.HOURS);
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .subject(user.getExternalSubject())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(expiresAt))
                .jwtID(UUID.randomUUID().toString())
                .claim("email", user.getEmail())
                .claim("name", user.getDisplayName());
        if (!roles.isEmpty()) {
            claims.claim("roles", roles.stream().sorted().toList());
        }
        if (tenant != null) {
            claims.claim("tenant_id", tenant.getId().toString());
            claims.claim("tenant_slug", tenant.getSlug());
        }
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims.build());
        try {
            jwt.sign(new MACSigner(hmacSecret));
        } catch (JOSEException ex) {
            throw new IllegalStateException("Failed to sign validation auth token", ex);
        }
        return new AuthSessionResponse(jwt.serialize(), "Bearer", expiresAt);
    }

    public String normalizeEmail(String email) {
        if (email == null || email.isBlank()) {
            throw invalidCredentials();
        }
        return email.trim().toLowerCase();
    }

    public String requirePassword(String password) {
        if (password == null || password.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password is required");
        }
        String normalized = password.trim();
        if (normalized.length() < 8) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password must be at least 8 characters");
        }
        return normalized;
    }

    public AppUser requireUserByEmail(String email) {
        return appUserRepository.findByEmailIgnoreCase(normalizeEmail(email))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invite user is not registered"));
    }

    private void requireHmacSecret() {
        if (hmacSecret.length < 32) {
            throw new IllegalStateException("APP_JWT_HMAC_SECRET must be set to at least 32 characters for validation auth.");
        }
    }

    private ResponseStatusException invalidCredentials() {
        return new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid email or password");
    }
}
