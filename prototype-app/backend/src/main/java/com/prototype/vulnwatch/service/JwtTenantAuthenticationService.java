package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantMembership;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@Service
public class JwtTenantAuthenticationService {

    private final AppUserRepository userRepository;
    private final TenantRepository tenantRepository;
    private final TenantMembershipRepository membershipRepository;
    private final TenantLifecycleGuardService tenantLifecycleGuardService;
    private final AppUserGlobalRoleService appUserGlobalRoleService;
    private final TenantSupportGrantService tenantSupportGrantService;
    private final String subjectClaim;
    private final String tenantIdClaim;
    private final String activeTenantIdClaim;
    private final String tenantSlugClaim;
    private final String emailClaim;
    private final String nameClaim;
    private final String rolesClaim;
    private final String keycloakClientId;

    public JwtTenantAuthenticationService(
            AppUserRepository userRepository,
            TenantRepository tenantRepository,
            TenantMembershipRepository membershipRepository,
            TenantLifecycleGuardService tenantLifecycleGuardService,
            AppUserGlobalRoleService appUserGlobalRoleService,
            TenantSupportGrantService tenantSupportGrantService,
            @Value("${app.security.jwt.subject-claim:sub}") String subjectClaim,
            @Value("${app.security.jwt.tenant-id-claim:tenant_id}") String tenantIdClaim,
            @Value("${app.security.jwt.active-tenant-id-claim:active_tenant_id}") String activeTenantIdClaim,
            @Value("${app.security.jwt.tenant-slug-claim:tenant_slug}") String tenantSlugClaim,
            @Value("${app.security.jwt.email-claim:email}") String emailClaim,
            @Value("${app.security.jwt.name-claim:name}") String nameClaim,
            @Value("${app.security.jwt.roles-claim:roles}") String rolesClaim,
            @Value("${app.security.jwt.keycloak-client-id:}") String keycloakClientId
    ) {
        this.userRepository = userRepository;
        this.tenantRepository = tenantRepository;
        this.membershipRepository = membershipRepository;
        this.tenantLifecycleGuardService = tenantLifecycleGuardService;
        this.appUserGlobalRoleService = appUserGlobalRoleService;
        this.tenantSupportGrantService = tenantSupportGrantService;
        this.subjectClaim = subjectClaim;
        this.tenantIdClaim = tenantIdClaim;
        this.activeTenantIdClaim = activeTenantIdClaim;
        this.tenantSlugClaim = tenantSlugClaim;
        this.emailClaim = emailClaim;
        this.nameClaim = nameClaim;
        this.rolesClaim = rolesClaim;
        this.keycloakClientId = keycloakClientId;
    }

    @Transactional
    public AuthenticatedTenantActor authenticate(Jwt jwt) {
        return authenticate(jwt, null);
    }

    @Transactional
    public AuthenticatedTenantActor authenticate(Jwt jwt, String requestUri) {
        String subject = resolveSubject(jwt);
        AppUser user = userRepository.findByExternalSubject(subject)
                .orElseGet(() -> createUser(subject));
        user.setEmail(claimAsString(jwt, emailClaim));
        user.setDisplayName(claimAsString(jwt, nameClaim));
        user.setLastSeenAt(Instant.now());
        user.setUpdatedAt(Instant.now());
        userRepository.save(user);

        Set<String> jwtRoles = extractJwtRoles(jwt);
        if (jwtRoles.contains("PLATFORM_OWNER")) {
            appUserGlobalRoleService.ensureRole(user, "PLATFORM_OWNER");
        }
        Set<String> roles = new LinkedHashSet<>(jwtRoles);
        roles.addAll(appUserGlobalRoleService.rolesForUser(user.getId()));
        if (roles.contains("PLATFORM_OWNER") && !user.isPlatformOwner()) {
            user.setPlatformOwner(true);
            user.setUpdatedAt(Instant.now());
            userRepository.save(user);
        }
        Tenant tenant = resolveTenant(jwt, subject, roles, requestUri);

        if (tenant != null) {
            TenantMembership membership = membershipRepository
                    .findFirstByUserExternalSubjectAndTenantIdAndStatus(subject, tenant.getId(), "ACTIVE")
                    .orElse(null);
            if (membership != null) {
                roles.add(membership.getRole());
            }
        }

        if (roles.isEmpty()) {
            roles.add("SECURITY_ANALYST");
        }

        return new AuthenticatedTenantActor(
                subject,
                user.getId(),
                user.getEmail(),
                user.getDisplayName(),
                tenant == null ? null : tenant.getId(),
                tenant == null ? null : tenant.getName(),
                tenant == null ? null : tenant.getSchemaName(),
                Set.copyOf(roles));
    }

    private Tenant resolveTenant(Jwt jwt, String subject, Set<String> roles, String requestUri) {
        String activeTenantId = claimAsString(jwt, activeTenantIdClaim);
        if (activeTenantId != null) {
            UUID tenantId = parseUuid(activeTenantId);
            Tenant tenant = tenantRepository.findById(tenantId)
                    .orElseThrow(() -> new ResponseStatusException(FORBIDDEN, "JWT active_tenant_id is not registered"));
            return requireSelectedTenantAccess(tenant, subject, roles);
        }

        String tenantId = claimAsString(jwt, tenantIdClaim);
        if (tenantId != null) {
            Tenant tenant = tenantRepository.findById(parseUuid(tenantId))
                    .orElseThrow(() -> new ResponseStatusException(FORBIDDEN, "JWT tenant_id is not registered"));
            return requireSelectedTenantAccess(tenant, subject, roles);
        }

        String tenantSlug = claimAsString(jwt, tenantSlugClaim);
        if (tenantSlug != null) {
            Tenant tenant = tenantRepository.findBySlugIgnoreCase(tenantSlug)
                    .orElseThrow(() -> new ResponseStatusException(FORBIDDEN, "JWT tenant_slug is not registered"));
            return requireSelectedTenantAccess(tenant, subject, roles);
        }

        if (roles.contains("PLATFORM_OWNER")) {
            return null;
        }

        List<TenantMembership> memberships = membershipRepository
                .findByUserExternalSubjectAndStatusOrderByCreatedAtAsc(subject, "ACTIVE");
        if (memberships.size() == 1) {
            Tenant tenant = memberships.get(0).getTenant();
            tenantLifecycleGuardService.assertTenantAccessible(tenant);
            return tenant;
        }
        if (memberships.size() > 1) {
            throw new ResponseStatusException(FORBIDDEN, "JWT user has multiple active tenant memberships");
        }
        throw new ResponseStatusException(FORBIDDEN, "JWT user does not have an active tenant membership");
    }

    private Tenant requireSelectedTenantAccess(Tenant tenant, String subject, Set<String> roles) {
        tenantLifecycleGuardService.assertTenantAccessible(tenant);
        if (roles.contains("PLATFORM_OWNER")) {
            tenantSupportGrantService.requireActiveGrant(subject, tenant.getId());
            return tenant;
        }
        TenantMembership membership = membershipRepository.findFirstByUserExternalSubjectAndTenantIdAndStatus(subject, tenant.getId(), "ACTIVE")
                .orElseThrow(() -> new ResponseStatusException(FORBIDDEN, "User is not an active member of the selected tenant"));
        roles.add(membership.getRole());
        return tenant;
    }

    private AppUser createUser(String subject) {
        AppUser user = new AppUser();
        user.setExternalSubject(subject);
        return user;
    }

    private String resolveSubject(Jwt jwt) {
        String configuredSubject = claimAsString(jwt, subjectClaim);
        if (hasText(configuredSubject)) {
            return configuredSubject;
        }
        return requireText(jwt.getSubject(), "JWT subject is required");
    }

    private Set<String> extractJwtRoles(Jwt jwt) {
        LinkedHashSet<String> roles = new LinkedHashSet<>(normalizeRoles(jwt.getClaim(rolesClaim)));
        if (!"roles".equals(rolesClaim)) {
            roles.addAll(normalizeRoles(jwt.getClaim("roles")));
        }
        // Some identity providers inject roles under a namespaced URI claim (e.g. https://example.com/roles).
        // Fall back to scanning all claims whose name ends with "/roles" when the configured claim yields nothing.
        if (roles.isEmpty()) {
            roles.addAll(extractNamespacedRoles(jwt));
        }
        roles.addAll(extractKeycloakRealmRoles(jwt));
        roles.addAll(extractKeycloakClientRoles(jwt));
        return roles;
    }

    private Set<String> extractNamespacedRoles(Jwt jwt) {
        Set<String> roles = new LinkedHashSet<>();
        jwt.getClaims().forEach((claimName, value) -> {
            if (claimName.endsWith("/roles")) {
                roles.addAll(normalizeRoles(value));
            }
        });
        return roles;
    }

    @SuppressWarnings("unchecked")
    private Set<String> extractKeycloakRealmRoles(Jwt jwt) {
        Object claim = jwt.getClaim("realm_access");
        if (!(claim instanceof Map<?, ?> access)) {
            return Set.of();
        }
        Object roles = access.get("roles");
        return normalizeRoles(roles);
    }

    @SuppressWarnings("unchecked")
    private Set<String> extractKeycloakClientRoles(Jwt jwt) {
        if (!hasText(keycloakClientId)) {
            return Set.of();
        }
        Object claim = jwt.getClaim("resource_access");
        if (!(claim instanceof Map<?, ?> access)) {
            return Set.of();
        }
        Object clientEntry = access.get(keycloakClientId);
        if (!(clientEntry instanceof Map<?, ?> clientAccess)) {
            return Set.of();
        }
        Object roles = clientAccess.get("roles");
        return normalizeRoles(roles);
    }

    private UUID parseUuid(String value) {
        try {
            return UUID.fromString(value.trim());
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(UNAUTHORIZED, "JWT tenant_id is not a UUID");
        }
    }

    private Set<String> normalizeRoles(Object claim) {
        Set<String> roles = new LinkedHashSet<>();
        if (claim instanceof String value) {
            for (String part : value.split("[, ]+")) {
                addRole(roles, part);
            }
        } else if (claim instanceof Collection<?> values) {
            values.forEach(value -> addRole(roles, String.valueOf(value)));
        }
        return roles;
    }

    private void addRole(Set<String> roles, String role) {
        if (role == null || role.isBlank()) {
            return;
        }
        roles.add(role.trim().toUpperCase(Locale.ROOT).replace('-', '_').replace(' ', '_').replaceFirst("^ROLE_", ""));
    }

    private String claimAsString(Jwt jwt, String claimName) {
        Object value = jwt.getClaim(claimName);
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value).trim();
        return text.isEmpty() ? null : text;
    }

    private String requireText(String value, String message) {
        if (value == null || value.isBlank()) {
            throw new ResponseStatusException(UNAUTHORIZED, message);
        }
        return value.trim();
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
