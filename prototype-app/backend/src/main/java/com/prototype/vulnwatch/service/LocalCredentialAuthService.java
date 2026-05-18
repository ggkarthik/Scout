package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantMembership;
import com.prototype.vulnwatch.dto.AuthTokenResponse;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class LocalCredentialAuthService {

    private final AppUserRepository userRepository;
    private final TenantRepository tenantRepository;
    private final TenantMembershipRepository membershipRepository;
    private final AuthTokenService authTokenService;
    private final TenantSupportGrantService tenantSupportGrantService;
    private final TenantLifecycleGuardService tenantLifecycleGuardService;
    private final String platformOwnerEmail;
    private final String platformOwnerPasswordHash;

    public LocalCredentialAuthService(
            AppUserRepository userRepository,
            TenantRepository tenantRepository,
            TenantMembershipRepository membershipRepository,
            AuthTokenService authTokenService,
            TenantSupportGrantService tenantSupportGrantService,
            TenantLifecycleGuardService tenantLifecycleGuardService,
            @Value("${app.security.local-auth.platform-owner-email:${APP_PLATFORM_OWNER_EMAIL:}}") String platformOwnerEmail,
            @Value("${app.security.local-auth.platform-owner-password-hash:${APP_PLATFORM_OWNER_PASSWORD_HASH:}}") String platformOwnerPasswordHash
    ) {
        this.userRepository = userRepository;
        this.tenantRepository = tenantRepository;
        this.membershipRepository = membershipRepository;
        this.authTokenService = authTokenService;
        this.tenantSupportGrantService = tenantSupportGrantService;
        this.tenantLifecycleGuardService = tenantLifecycleGuardService;
        this.platformOwnerEmail = platformOwnerEmail;
        this.platformOwnerPasswordHash = platformOwnerPasswordHash;
    }

    @Transactional
    public AuthTokenResponse login(String email, String password) {
        String normalizedEmail = normalizeEmail(email);
        String rawPassword = requirePassword(password);
        if (matchesPlatformOwner(normalizedEmail)) {
            verifyPassword(rawPassword, requirePlatformOwnerPasswordHash());
            AppUser user = userRepository.findByExternalSubject(normalizedEmail)
                    .or(() -> userRepository.findByEmailIgnoreCase(normalizedEmail))
                    .orElseGet(() -> createUser(normalizedEmail));
            user.setEmail(normalizedEmail);
            user.setDisplayName(user.getDisplayName() == null || user.getDisplayName().isBlank() ? "Platform Owner" : user.getDisplayName());
            user.setPlatformOwner(true);
            user.setStatus("ACTIVE");
            user.setLastSeenAt(Instant.now());
            user.setUpdatedAt(Instant.now());
            userRepository.save(user);
            return authTokenService.issueToken(user, Set.of("PLATFORM_OWNER"), null);
        }

        AppUser user = userRepository.findByEmailIgnoreCase(normalizedEmail)
                .orElseThrow(() -> invalidCredentials());
        if (user.getPasswordHash() == null || user.getPasswordHash().isBlank()) {
            throw invalidCredentials();
        }
        verifyPassword(rawPassword, user.getPasswordHash());
        List<TenantMembership> memberships = membershipRepository
                .findByUserExternalSubjectAndStatusOrderByCreatedAtAsc(user.getExternalSubject(), "ACTIVE");
        if (memberships.size() != 1) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Tenant owner must have exactly one active tenant");
        }
        TenantMembership membership = memberships.get(0);
        tenantLifecycleGuardService.assertTenantAccessible(membership.getTenant());
        user.setLastSeenAt(Instant.now());
        user.setUpdatedAt(Instant.now());
        userRepository.save(user);
        return authTokenService.issueToken(user, Set.of(normalizeRole(membership.getRole())), membership.getTenant());
    }

    @Transactional
    public AuthTokenResponse setupPassword(String setupToken, String password) {
        String normalizedToken = requireText(setupToken, "setupToken");
        AppUser user = userRepository.findByPasswordSetupTokenHash(hashToken(normalizedToken))
                .orElseThrow(this::invalidSetupToken);
        if (user.getPasswordSetupTokenExpiresAt() == null || !user.getPasswordSetupTokenExpiresAt().isAfter(Instant.now())) {
            clearSetupToken(user);
            throw invalidSetupToken();
        }
        user.setPasswordHash(BCrypt.hashpw(requirePassword(password), BCrypt.gensalt(10)));
        user.setPasswordSetAt(Instant.now());
        clearSetupToken(user);
        user.setUpdatedAt(Instant.now());
        userRepository.save(user);

        List<TenantMembership> memberships = membershipRepository
                .findByUserExternalSubjectAndStatusOrderByCreatedAtAsc(user.getExternalSubject(), "ACTIVE");
        if (memberships.size() != 1) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Tenant owner must have exactly one active tenant");
        }
        TenantMembership membership = memberships.get(0);
        tenantLifecycleGuardService.assertTenantAccessible(membership.getTenant());
        return authTokenService.issueToken(user, Set.of(normalizeRole(membership.getRole())), membership.getTenant());
    }

    @Transactional
    public AuthTokenResponse switchTenantContext(String subject, UUID tenantId) {
        AppUser user = userRepository.findByExternalSubject(requireText(subject, "subject"))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Authenticated user is not registered"));
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Tenant not found"));
        tenantLifecycleGuardService.assertTenantAccessible(tenant);
        tenantSupportGrantService.requireActiveGrant(user.getExternalSubject(), tenantId);
        return authTokenService.issueToken(user, Set.of("PLATFORM_OWNER"), tenant);
    }

    @Transactional
    public AuthTokenResponse clearTenantContext(String subject) {
        AppUser user = userRepository.findByExternalSubject(requireText(subject, "subject"))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Authenticated user is not registered"));
        return authTokenService.issueToken(user, Set.of("PLATFORM_OWNER"), null);
    }

    @Transactional
    public String issuePasswordSetupToken(String subject) {
        AppUser user = userRepository.findByExternalSubject(requireText(subject, "subject"))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Invited user not found"));
        String token = UUID.randomUUID() + "-" + UUID.randomUUID();
        user.setPasswordSetupTokenHash(hashToken(token));
        user.setPasswordSetupTokenExpiresAt(Instant.now().plus(7, ChronoUnit.DAYS));
        user.setUpdatedAt(Instant.now());
        userRepository.save(user);
        return token;
    }

    private void clearSetupToken(AppUser user) {
        user.setPasswordSetupTokenHash(null);
        user.setPasswordSetupTokenExpiresAt(null);
    }

    private String requirePlatformOwnerPasswordHash() {
        if (platformOwnerPasswordHash == null || platformOwnerPasswordHash.isBlank()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Platform owner password hash is not configured");
        }
        return platformOwnerPasswordHash.trim();
    }

    private boolean matchesPlatformOwner(String email) {
        return platformOwnerEmail != null
                && !platformOwnerEmail.isBlank()
                && platformOwnerEmail.trim().equalsIgnoreCase(email);
    }

    private void verifyPassword(String rawPassword, String passwordHash) {
        if (!BCrypt.checkpw(rawPassword, passwordHash)) {
            throw invalidCredentials();
        }
    }

    private AppUser createUser(String externalSubject) {
        AppUser user = new AppUser();
        user.setExternalSubject(externalSubject);
        return user;
    }

    private String normalizeRole(String role) {
        return requireText(role, "role").toUpperCase().replace('-', '_').replace(' ', '_').replaceFirst("^ROLE_", "");
    }

    private String normalizeEmail(String value) {
        return requireText(value, "email").toLowerCase();
    }

    private String requirePassword(String value) {
        if (value == null || value.isBlank()) {
            throw invalidCredentials();
        }
        return value;
    }

    private String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, field + " is required");
        }
        return value.trim();
    }

    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to issue password setup token");
        }
    }

    private ResponseStatusException invalidCredentials() {
        return new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid email or password");
    }

    private ResponseStatusException invalidSetupToken() {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password setup token is invalid or expired");
    }
}
