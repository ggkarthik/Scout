package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class JwtTenantAuthenticationServiceTest {

    @Mock
    AppUserRepository userRepository;

    @Mock
    TenantRepository tenantRepository;

    @Mock
    TenantMembershipRepository membershipRepository;
    @Mock
    TenantLifecycleGuardService tenantLifecycleGuardService;
    @Mock
    AppUserGlobalRoleService appUserGlobalRoleService;
    @Mock
    TenantSupportGrantService tenantSupportGrantService;

    @Test
    void platformOwnerJwtWithoutExplicitTenantStaysTenantless() {
        AppUser user = new AppUser();
        user.setId(java.util.UUID.randomUUID());
        user.setExternalSubject("owner@example.com");

        when(userRepository.findByExternalSubject("owner@example.com")).thenReturn(Optional.of(user));
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(appUserGlobalRoleService.rolesForUser(user.getId())).thenReturn(Set.of());

        JwtTenantAuthenticationService service = new JwtTenantAuthenticationService(
                userRepository,
                tenantRepository,
                membershipRepository,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                tenantSupportGrantService,
                "sub",
                "tenant_id",
                "active_tenant_id",
                "tenant_slug",
                "email",
                "name",
                "roles",
                "scout-ui");

        AuthenticatedTenantActor actor = service.authenticate(Jwt.withTokenValue("token")
                .header("alg", "HS256")
                .subject("owner@example.com")
                .claim("email", "owner@example.com")
                .claim("roles", List.of("PLATFORM_OWNER"))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build());

        assertEquals("owner@example.com", actor.subject());
        assertNull(actor.tenantId());
        assertNull(actor.tenantName());
        assertEquals(Set.of("PLATFORM_OWNER"), actor.roles());
    }

    @Test
    void keycloakRealmRolePromotesPlatformOwnerAndSyncsRole() {
        AppUser user = new AppUser();
        user.setId(java.util.UUID.randomUUID());
        user.setExternalSubject("kc-owner");

        when(userRepository.findByExternalSubject("kc-owner")).thenReturn(Optional.of(user));
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(appUserGlobalRoleService.rolesForUser(user.getId())).thenReturn(Set.of("PLATFORM_OWNER"));

        JwtTenantAuthenticationService service = new JwtTenantAuthenticationService(
                userRepository,
                tenantRepository,
                membershipRepository,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                tenantSupportGrantService,
                "sub",
                "tenant_id",
                "active_tenant_id",
                "tenant_slug",
                "email",
                "name",
                "roles",
                "scout-ui");

        AuthenticatedTenantActor actor = service.authenticate(Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .subject("kc-owner")
                .claim("email", "owner@example.com")
                .claim("realm_access", Map.of("roles", List.of("platform-owner")))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build());

        assertEquals(Set.of("PLATFORM_OWNER"), actor.roles());
        verify(appUserGlobalRoleService).ensureRole(user, "PLATFORM_OWNER");
    }

    @Test
    void storedGlobalRoleSupportsPlatformScopeWithoutJwtRole() {
        AppUser user = new AppUser();
        user.setId(java.util.UUID.randomUUID());
        user.setExternalSubject("stored-owner");

        when(userRepository.findByExternalSubject("stored-owner")).thenReturn(Optional.of(user));
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(appUserGlobalRoleService.rolesForUser(user.getId())).thenReturn(Set.of("PLATFORM_OWNER"));

        JwtTenantAuthenticationService service = new JwtTenantAuthenticationService(
                userRepository,
                tenantRepository,
                membershipRepository,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                tenantSupportGrantService,
                "sub",
                "tenant_id",
                "active_tenant_id",
                "tenant_slug",
                "email",
                "name",
                "roles",
                "scout-ui");

        AuthenticatedTenantActor actor = service.authenticate(Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .subject("stored-owner")
                .claim("email", "stored-owner@example.com")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build());

        assertEquals(Set.of("PLATFORM_OWNER"), actor.roles());
        assertNull(actor.tenantId());
    }

    @Test
    void namespacedRolesClaimSupportsPlatformOwnerTokens() {
        AppUser user = new AppUser();
        user.setId(java.util.UUID.randomUUID());
        user.setExternalSubject("owner@example.com");

        when(userRepository.findByExternalSubject("owner@example.com")).thenReturn(Optional.of(user));
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(appUserGlobalRoleService.rolesForUser(user.getId())).thenReturn(Set.of("PLATFORM_OWNER"));

        JwtTenantAuthenticationService service = new JwtTenantAuthenticationService(
                userRepository,
                tenantRepository,
                membershipRepository,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                tenantSupportGrantService,
                "email",
                "tenant_id",
                "active_tenant_id",
                "tenant_slug",
                "email",
                "name",
                "https://hossstore.in/roles",
                "scout-ui");

        AuthenticatedTenantActor actor = service.authenticate(Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .subject("owner-subject-123")
                .claim("email", "owner@example.com")
                .claim("https://hossstore.in/roles", List.of("PLATFORM_OWNER"))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build());

        assertEquals("owner@example.com", actor.subject());
        assertEquals(Set.of("PLATFORM_OWNER"), actor.roles());
        verify(appUserGlobalRoleService).ensureRole(user, "PLATFORM_OWNER");
    }

    @Test
    void platformOwnerActiveTenantContextRequiresGrantAndSwitchesTenant() {
        AppUser user = new AppUser();
        user.setId(UUID.randomUUID());
        user.setExternalSubject("owner@example.com");
        UUID tenantId = UUID.fromString("11111111-1111-1111-1111-111111111111");
        Tenant tenant = new Tenant();
        tenant.setId(tenantId);
        tenant.setName("Acme");
        tenant.setSchemaName("tenant_acme");

        when(userRepository.findByExternalSubject("owner@example.com")).thenReturn(Optional.of(user));
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(appUserGlobalRoleService.rolesForUser(user.getId())).thenReturn(Set.of("PLATFORM_OWNER"));
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));

        JwtTenantAuthenticationService service = new JwtTenantAuthenticationService(
                userRepository,
                tenantRepository,
                membershipRepository,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                tenantSupportGrantService,
                "sub",
                "tenant_id",
                "active_tenant_id",
                "tenant_slug",
                "email",
                "name",
                "roles",
                "scout-ui");

        AuthenticatedTenantActor actor = service.authenticate(Jwt.withTokenValue("token")
                        .header("alg", "HS256")
                        .subject("owner@example.com")
                        .claim("email", "owner@example.com")
                        .claim("roles", List.of("PLATFORM_OWNER"))
                        .claim("active_tenant_id", tenantId.toString())
                        .issuedAt(Instant.now())
                        .expiresAt(Instant.now().plusSeconds(3600))
                        .build(),
                "/api/ingestion/nvd-sync");

        assertEquals(tenantId, actor.tenantId());
        assertEquals("Acme", actor.tenantName());
        verify(tenantSupportGrantService).requireActiveGrant("owner@example.com", tenantId);
    }

    @Test
    void platformOwnerTenantIdClaimWithoutGrantIsDenied() {
        AppUser user = new AppUser();
        user.setId(UUID.randomUUID());
        user.setExternalSubject("owner@example.com");
        UUID tenantId = UUID.fromString("22222222-2222-2222-2222-222222222222");
        Tenant tenant = new Tenant();
        tenant.setId(tenantId);
        tenant.setName("Beta");
        tenant.setSchemaName("tenant_beta");

        when(userRepository.findByExternalSubject("owner@example.com")).thenReturn(Optional.of(user));
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(appUserGlobalRoleService.rolesForUser(user.getId())).thenReturn(Set.of("PLATFORM_OWNER"));
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        doThrow(new ResponseStatusException(org.springframework.http.HttpStatus.FORBIDDEN, "no grant"))
                .when(tenantSupportGrantService).requireActiveGrant("owner@example.com", tenantId);

        JwtTenantAuthenticationService service = new JwtTenantAuthenticationService(
                userRepository,
                tenantRepository,
                membershipRepository,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                tenantSupportGrantService,
                "sub",
                "tenant_id",
                "active_tenant_id",
                "tenant_slug",
                "email",
                "name",
                "roles",
                "scout-ui");

        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "HS256")
                .subject("owner@example.com")
                .claim("email", "owner@example.com")
                .claim("roles", List.of("PLATFORM_OWNER"))
                .claim("tenant_id", tenantId.toString())
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();

        assertThrows(ResponseStatusException.class, () -> service.authenticate(jwt));
    }
}
