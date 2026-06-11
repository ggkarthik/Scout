package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantMembership;
import com.prototype.vulnwatch.dto.AuthTokenResponse;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
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

    private static final String DEFAULT_LOCALHOST_PLATFORM_OWNER_EMAIL = "platform.owner@localhost";
    private static final String DEFAULT_LOCALHOST_PLATFORM_OWNER_PASSWORD_HASH = "$2a$10$awIpunHkac/hB/2JPslHL.KAAtdZ5.rmmkqVjxlHkmaPHXJ1OCKPO";
    private static final String DEFAULT_LOCALHOST_TENANT_ADMIN_EMAIL = "tenant.admin@localhost";
    private static final String DEFAULT_LOCALHOST_TENANT_ADMIN_PASSWORD_HASH = "$2a$10$6cfZYpOkQxrSl3.YCGYTPutGAORvx.ywRJmp7EkD9SYO5LLvqrhaO";

    private final AppUserRepository userRepository;
    private final TenantRepository tenantRepository;
    private final TenantMembershipRepository membershipRepository;
    private final AuthTokenService authTokenService;
    private final TenantSupportGrantService tenantSupportGrantService;
    private final TenantLifecycleGuardService tenantLifecycleGuardService;
    private final AppUserGlobalRoleService appUserGlobalRoleService;
    private final String platformOwnerEmail;
    private final String platformOwnerPasswordHash;
    private final boolean requireProductionSecrets;
    private final boolean sharedLocalhostLoginEnabled;
    private final String sharedLocalhostPlatformOwnerEmail;
    private final String sharedLocalhostPlatformOwnerPasswordHash;
    private final String sharedLocalhostTenantAdminEmail;
    private final String sharedLocalhostTenantAdminPasswordHash;
    private final boolean sharedLocalhostEnvironment;

    public LocalCredentialAuthService(
            AppUserRepository userRepository,
            TenantRepository tenantRepository,
            TenantMembershipRepository membershipRepository,
            AuthTokenService authTokenService,
            TenantSupportGrantService tenantSupportGrantService,
            TenantLifecycleGuardService tenantLifecycleGuardService,
            AppUserGlobalRoleService appUserGlobalRoleService,
            @Value("${app.security.require-production-secrets:false}") boolean requireProductionSecrets,
            @Value("${app.security.local-auth.platform-owner-email:${APP_PLATFORM_OWNER_EMAIL:}}") String platformOwnerEmail,
            @Value("${app.security.local-auth.platform-owner-password-hash:${APP_PLATFORM_OWNER_PASSWORD_HASH:}}") String platformOwnerPasswordHash,
            @Value("${app.security.local-auth.shared-localhost-login-enabled:true}") boolean sharedLocalhostLoginEnabled,
            @Value("${app.security.local-auth.shared-localhost-platform-owner-email:}") String sharedLocalhostPlatformOwnerEmail,
            @Value("${app.security.local-auth.shared-localhost-platform-owner-password-hash:}") String sharedLocalhostPlatformOwnerPasswordHash,
            @Value("${app.security.local-auth.shared-localhost-tenant-admin-email:}") String sharedLocalhostTenantAdminEmail,
            @Value("${app.security.local-auth.shared-localhost-tenant-admin-password-hash:}") String sharedLocalhostTenantAdminPasswordHash,
            @Value("${app.cors.allowed-origins:}") String corsAllowedOrigins
    ) {
        this.userRepository = userRepository;
        this.tenantRepository = tenantRepository;
        this.membershipRepository = membershipRepository;
        this.authTokenService = authTokenService;
        this.tenantSupportGrantService = tenantSupportGrantService;
        this.tenantLifecycleGuardService = tenantLifecycleGuardService;
        this.appUserGlobalRoleService = appUserGlobalRoleService;
        this.requireProductionSecrets = requireProductionSecrets;
        this.platformOwnerEmail = platformOwnerEmail;
        this.platformOwnerPasswordHash = platformOwnerPasswordHash;
        this.sharedLocalhostLoginEnabled = sharedLocalhostLoginEnabled;
        this.sharedLocalhostPlatformOwnerEmail = defaultIfBlank(
                sharedLocalhostPlatformOwnerEmail,
                DEFAULT_LOCALHOST_PLATFORM_OWNER_EMAIL
        );
        this.sharedLocalhostPlatformOwnerPasswordHash = defaultIfBlank(
                sharedLocalhostPlatformOwnerPasswordHash,
                DEFAULT_LOCALHOST_PLATFORM_OWNER_PASSWORD_HASH
        );
        this.sharedLocalhostTenantAdminEmail = defaultIfBlank(
                sharedLocalhostTenantAdminEmail,
                DEFAULT_LOCALHOST_TENANT_ADMIN_EMAIL
        );
        this.sharedLocalhostTenantAdminPasswordHash = defaultIfBlank(
                sharedLocalhostTenantAdminPasswordHash,
                DEFAULT_LOCALHOST_TENANT_ADMIN_PASSWORD_HASH
        );
        this.sharedLocalhostEnvironment = detectSharedLocalhostEnvironment(corsAllowedOrigins);
    }

    @Transactional
    public AuthTokenResponse login(String email, String password) {
        String normalizedEmail = normalizeEmail(email);
        String rawPassword = requirePassword(password);
        if (matchesPlatformOwner(normalizedEmail)) {
            verifyPassword(rawPassword, requirePlatformOwnerPasswordHash());
            return loginPlatformOwner(normalizedEmail, "Platform Owner");
        }

        AppUser user = userRepository.findByEmailIgnoreCase(normalizedEmail).orElse(null);
        if (user != null && hasText(user.getPasswordHash())) {
            verifyPassword(rawPassword, user.getPasswordHash());
            return loginTenantScopedUser(user);
        }

        if (matchesSharedLocalhostPlatformOwner(normalizedEmail)) {
            verifyPassword(rawPassword, sharedLocalhostPlatformOwnerPasswordHash);
            return loginPlatformOwner(normalizedEmail, "Local Platform Owner");
        }

        if (matchesSharedLocalhostTenantAdmin(normalizedEmail)) {
            verifyPassword(rawPassword, sharedLocalhostTenantAdminPasswordHash);
            return loginSharedLocalhostTenantAdmin(normalizedEmail);
        }

        if (user == null) {
            throw invalidCredentials();
        }
        if (!hasText(user.getPasswordHash())) {
            throw invalidCredentials();
        }
        verifyPassword(rawPassword, user.getPasswordHash());
        return loginTenantScopedUser(user);
    }

    private AuthTokenResponse loginTenantScopedUser(AppUser user) {
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

    private AuthTokenResponse loginPlatformOwner(String normalizedEmail, String defaultDisplayName) {
        AppUser user = userRepository.findByExternalSubject(normalizedEmail)
                .or(() -> userRepository.findByEmailIgnoreCase(normalizedEmail))
                .orElseGet(() -> createUser(normalizedEmail));
        user.setEmail(normalizedEmail);
        user.setDisplayName(user.getDisplayName() == null || user.getDisplayName().isBlank() ? defaultDisplayName : user.getDisplayName());
        user.setPlatformOwner(true);
        user.setStatus("ACTIVE");
        user.setLastSeenAt(Instant.now());
        user.setUpdatedAt(Instant.now());
        userRepository.save(user);
        appUserGlobalRoleService.ensureRole(user, "PLATFORM_OWNER");
        return authTokenService.issueToken(user, Set.of("PLATFORM_OWNER"), null);
    }

    private AuthTokenResponse loginSharedLocalhostTenantAdmin(String normalizedEmail) {
        Tenant tenant = tenantRepository.findByNameIgnoreCase(TenantService.DEFAULT_TENANT_NAME)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.CONFLICT, "Default workspace is not bootstrapped"));
        tenantLifecycleGuardService.assertTenantAccessible(tenant);

        AppUser user = userRepository.findByExternalSubject(normalizedEmail)
                .or(() -> userRepository.findByEmailIgnoreCase(normalizedEmail))
                .orElseGet(() -> createUser(normalizedEmail));
        user.setEmail(normalizedEmail);
        user.setDisplayName(user.getDisplayName() == null || user.getDisplayName().isBlank() ? "Local Tenant Admin" : user.getDisplayName());
        user.setStatus("ACTIVE");
        user.setPasswordHash(sharedLocalhostTenantAdminPasswordHash);
        user.setPasswordSetAt(user.getPasswordSetAt() == null ? Instant.now() : user.getPasswordSetAt());
        user.setLastSeenAt(Instant.now());
        user.setUpdatedAt(Instant.now());
        userRepository.save(user);

        TenantMembership membership = membershipRepository
                .findFirstByUserExternalSubjectAndTenantIdAndStatus(user.getExternalSubject(), tenant.getId(), "ACTIVE")
                .map(existing -> {
                    existing.setRole("TENANT_ADMIN");
                    existing.setUpdatedAt(Instant.now());
                    return membershipRepository.save(existing);
                })
                .orElseGet(() -> {
                    TenantMembership created = new TenantMembership();
                    created.setTenant(tenant);
                    created.setUser(user);
                    created.setRole("TENANT_ADMIN");
                    return membershipRepository.save(created);
                });
        return authTokenService.issueToken(user, Set.of(normalizeRole(membership.getRole())), tenant);
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

    private boolean matchesSharedLocalhostPlatformOwner(String email) {
        return sharedLocalhostEnvironment
                && sharedLocalhostPlatformOwnerEmail.equalsIgnoreCase(email);
    }

    private boolean matchesSharedLocalhostTenantAdmin(String email) {
        return sharedLocalhostEnvironment
                && sharedLocalhostTenantAdminEmail.equalsIgnoreCase(email);
    }

    private boolean detectSharedLocalhostEnvironment(String corsAllowedOrigins) {
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

    private boolean isLoopbackHost(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        return "localhost".equals(normalized)
                || "127.0.0.1".equals(normalized)
                || "::1".equals(normalized)
                || "0:0:0:0:0:0:0:1".equals(normalized)
                || "[::1]".equals(normalized);
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

    private String defaultIfBlank(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value.trim();
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
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
