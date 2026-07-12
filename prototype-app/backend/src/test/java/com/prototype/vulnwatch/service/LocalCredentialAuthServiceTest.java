package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class LocalCredentialAuthServiceTest {

    private static final String SECRET = "phase-1-local-auth-secret-32-bytes";

    @Mock
    private AppUserRepository userRepository;

    @Mock
    private TenantRepository tenantRepository;

    @Mock
    private TenantMembershipRepository membershipRepository;

    @Mock
    private TenantSupportGrantService tenantSupportGrantService;
    @Mock
    private TenantLifecycleGuardService tenantLifecycleGuardService;
    @Mock
    private AppUserGlobalRoleService appUserGlobalRoleService;
    @Mock
    private AuditEventService auditEventService;

    @Test
    void platformOwnerLoginReturnsPlatformScopeToken() {
        AppUser existingUser = new AppUser();
        existingUser.setExternalSubject("owner@example.com");
        existingUser.setEmail("owner@example.com");
        existingUser.setPasswordHash(BCrypt.hashpw("password-123", BCrypt.gensalt(10)));
        existingUser.setPlatformOwner(true);

        when(userRepository.findByEmailIgnoreCase("owner@example.com")).thenReturn(Optional.of(existingUser));
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));

        LocalCredentialAuthService service = new LocalCredentialAuthService(
                userRepository,
                tenantRepository,
                membershipRepository,
                authTokenService(),
                tenantSupportGrantService,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                auditEventService,
                false,
                true,
                "",
                "",
                "http://localhost:5173,http://127.0.0.1:5173"
        );

        AuthTokenResponse response = service.login("OWNER@example.com", "password-123");
        Jwt jwt = decode(response.token());

        assertEquals("owner@example.com", jwt.getSubject());
        assertEquals("PLATFORM_OWNER", jwt.getClaimAsStringList("roles").get(0));
        assertNull(jwt.getClaimAsString("active_tenant_id"));
        assertTrue(existingUser.isPlatformOwner());
        verify(userRepository).save(existingUser);
        verify(appUserGlobalRoleService).ensureRole(existingUser, "PLATFORM_OWNER");
    }

    @Test
    void tenantOwnerLoginReturnsSingleTenantContext() {
        AppUser user = new AppUser();
        user.setExternalSubject("tenant.owner@example.com");
        user.setEmail("tenant.owner@example.com");
        user.setPasswordHash(BCrypt.hashpw("password-123", BCrypt.gensalt(10)));

        Tenant tenant = tenant("Example Co");
        TenantMembership membership = membership(user, tenant, "TENANT_ADMIN");

        when(userRepository.findByEmailIgnoreCase("tenant.owner@example.com")).thenReturn(Optional.of(user));
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(membershipRepository.findByUserExternalSubjectAndStatusOrderByCreatedAtAsc("tenant.owner@example.com", "ACTIVE"))
                .thenReturn(List.of(membership));

        LocalCredentialAuthService service = new LocalCredentialAuthService(
                userRepository,
                tenantRepository,
                membershipRepository,
                authTokenService(),
                tenantSupportGrantService,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                auditEventService,
                false,
                true,
                "",
                "",
                "http://localhost:5173,http://127.0.0.1:5173"
        );

        AuthTokenResponse response = service.login("tenant.owner@example.com", "password-123");
        Jwt jwt = decode(response.token());

        assertEquals("tenant.owner@example.com", jwt.getSubject());
        assertEquals(tenant.getId().toString(), jwt.getClaimAsString("active_tenant_id"));
        assertEquals("TENANT_ADMIN", jwt.getClaimAsStringList("roles").get(0));
    }

    @Test
    void passwordSetupWorksExactlyOnce() {
        AppUser user = new AppUser();
        user.setExternalSubject("tenant.owner@example.com");
        user.setEmail("tenant.owner@example.com");
        user.setPasswordSetupTokenHash(hashToken("setup-token-123"));
        user.setPasswordSetupTokenExpiresAt(Instant.now().plusSeconds(3600));

        Tenant tenant = tenant("Example Co");
        TenantMembership membership = membership(user, tenant, "TENANT_ADMIN");

        when(userRepository.findByPasswordSetupTokenHash(hashToken("setup-token-123"))).thenReturn(Optional.of(user));
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(membershipRepository.findByUserExternalSubjectAndStatusOrderByCreatedAtAsc("tenant.owner@example.com", "ACTIVE"))
                .thenReturn(List.of(membership));

        LocalCredentialAuthService service = new LocalCredentialAuthService(
                userRepository,
                tenantRepository,
                membershipRepository,
                authTokenService(),
                tenantSupportGrantService,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                auditEventService,
                false,
                true,
                "",
                "",
                "http://localhost:5173,http://127.0.0.1:5173"
        );

        AuthTokenResponse response = service.setupPassword("setup-token-123", "password-123");
        Jwt jwt = decode(response.token());

        assertEquals(tenant.getId().toString(), jwt.getClaimAsString("active_tenant_id"));
        assertTrue(BCrypt.checkpw("password-123", user.getPasswordHash()));
        assertNull(user.getPasswordSetupTokenHash());
        assertNull(user.getPasswordSetupTokenExpiresAt());

        ResponseStatusException error = assertThrows(
                ResponseStatusException.class,
                () -> service.setupPassword("setup-token-123", "password-456")
        );
        assertEquals(400, error.getStatusCode().value());
    }

    @Test
    void platformOwnerPasswordSetupReturnsPlatformScopeToken() {
        AppUser user = new AppUser();
        user.setExternalSubject("owner@example.com");
        user.setEmail("owner@example.com");
        user.setPlatformOwner(true);
        user.setPasswordSetupTokenHash(hashToken("setup-token-123"));
        user.setPasswordSetupTokenExpiresAt(Instant.now().plusSeconds(3600));

        when(userRepository.findByPasswordSetupTokenHash(hashToken("setup-token-123"))).thenReturn(Optional.of(user));
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));

        LocalCredentialAuthService service = new LocalCredentialAuthService(
                userRepository,
                tenantRepository,
                membershipRepository,
                authTokenService(),
                tenantSupportGrantService,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                auditEventService,
                false,
                true,
                "",
                "",
                "http://localhost:5173,http://127.0.0.1:5173"
        );

        AuthTokenResponse response = service.setupPassword("setup-token-123", "password-123");
        Jwt jwt = decode(response.token());

        assertEquals("owner@example.com", jwt.getSubject());
        assertNull(jwt.getClaimAsString("active_tenant_id"));
        assertEquals("PLATFORM_OWNER", jwt.getClaimAsStringList("roles").get(0));
        assertTrue(BCrypt.checkpw("password-123", user.getPasswordHash()));
        verify(auditEventService).recordExplicitActor(
                null,
                "owner@example.com",
                "PLATFORM_OWNER",
                "platform.user.setup_completed",
                "app_user",
                user.getId().toString(),
                "{\"mode\":\"self_service\"}",
                "SUCCESS"
        );
        verify(appUserGlobalRoleService).ensureRole(user, "PLATFORM_OWNER");
    }

    @Test
    void platformOwnerWithoutPasswordHashCannotUseRemovedSharedLocalhostFallback() {
        AppUser user = new AppUser();
        user.setExternalSubject("owner@example.com");
        user.setEmail("owner@example.com");
        user.setPlatformOwner(true);

        when(userRepository.findByEmailIgnoreCase("owner@example.com")).thenReturn(Optional.of(user));

        LocalCredentialAuthService service = new LocalCredentialAuthService(
                userRepository,
                tenantRepository,
                membershipRepository,
                authTokenService(),
                tenantSupportGrantService,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                auditEventService,
                false,
                true,
                "",
                "",
                "http://localhost:5173,http://127.0.0.1:5173"
        );

        assertThrows(ResponseStatusException.class, () -> service.login("owner@example.com", "password-123"));
    }

    @Test
    void switchTenantContextRequiresActiveGrantAndIssuesTenantBoundToken() {
        AppUser platformOwner = new AppUser();
        platformOwner.setExternalSubject("owner@example.com");
        platformOwner.setEmail("owner@example.com");
        Tenant tenant = tenant("Customer A");

        when(userRepository.findByExternalSubject("owner@example.com")).thenReturn(Optional.of(platformOwner));
        when(tenantRepository.findById(tenant.getId())).thenReturn(Optional.of(tenant));

        LocalCredentialAuthService service = new LocalCredentialAuthService(
                userRepository,
                tenantRepository,
                membershipRepository,
                authTokenService(),
                tenantSupportGrantService,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                auditEventService,
                false,
                true,
                "",
                "",
                "http://localhost:5173,http://127.0.0.1:5173"
        );

        AuthTokenResponse response = service.switchTenantContext("owner@example.com", tenant.getId());
        Jwt jwt = decode(response.token());

        verify(tenantSupportGrantService).requireActiveGrant("owner@example.com", tenant.getId());
        assertEquals(tenant.getId().toString(), jwt.getClaimAsString("active_tenant_id"));
        assertEquals("PLATFORM_OWNER", jwt.getClaimAsStringList("roles").get(0));
    }

    @Test
    void switchTenantContextUsesExplicitTenantMembershipForInternalPlaygroundAccess() {
        AppUser platformOwner = new AppUser();
        platformOwner.setExternalSubject("owner@example.com");
        platformOwner.setEmail("owner@example.com");
        platformOwner.setPlatformOwner(true);
        Tenant tenant = tenant("Default Workspace");
        TenantMembership membership = membership(platformOwner, tenant, "TENANT_ADMIN");

        when(userRepository.findByExternalSubject("owner@example.com")).thenReturn(Optional.of(platformOwner));
        when(tenantRepository.findById(tenant.getId())).thenReturn(Optional.of(tenant));
        when(membershipRepository.findFirstByUserExternalSubjectAndTenantIdAndStatus(
                "owner@example.com",
                tenant.getId(),
                "ACTIVE"
        )).thenReturn(Optional.of(membership));

        LocalCredentialAuthService service = new LocalCredentialAuthService(
                userRepository,
                tenantRepository,
                membershipRepository,
                authTokenService(),
                tenantSupportGrantService,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                auditEventService,
                false,
                true,
                "",
                "",
                "http://localhost:5173,http://127.0.0.1:5173"
        );

        AuthTokenResponse response = service.switchTenantContext("owner@example.com", tenant.getId());
        Jwt jwt = decode(response.token());

        assertEquals(tenant.getId().toString(), jwt.getClaimAsString("active_tenant_id"));
        assertTrue(jwt.getClaimAsStringList("roles").contains("PLATFORM_OWNER"));
        assertTrue(jwt.getClaimAsStringList("roles").contains("TENANT_ADMIN"));
        verifyNoInteractions(tenantSupportGrantService);
    }

    @Test
    void clearTenantContextIssuesFreshPlatformScopeToken() {
        AppUser platformOwner = new AppUser();
        platformOwner.setExternalSubject("owner@example.com");
        platformOwner.setEmail("owner@example.com");
        when(userRepository.findByExternalSubject("owner@example.com")).thenReturn(Optional.of(platformOwner));

        LocalCredentialAuthService service = new LocalCredentialAuthService(
                userRepository,
                tenantRepository,
                membershipRepository,
                authTokenService(),
                tenantSupportGrantService,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                auditEventService,
                false,
                true,
                "",
                "",
                "http://localhost:5173,http://127.0.0.1:5173"
        );

        AuthTokenResponse response = service.clearTenantContext("owner@example.com");
        Jwt jwt = decode(response.token());

        assertNull(jwt.getClaimAsString("active_tenant_id"));
        assertEquals("PLATFORM_OWNER", jwt.getClaimAsStringList("roles").get(0));
    }

    @Test
    void localhostSharedTenantAdminLoginBootstrapsDefaultWorkspaceMembership() {
        Tenant tenant = tenant("Default Workspace");
        AppUser user = new AppUser();
        user.setExternalSubject("tenant.admin@localhost");
        user.setEmail("tenant.admin@localhost");

        when(tenantRepository.findByNameIgnoreCase("Default Workspace")).thenReturn(Optional.of(tenant));
        when(userRepository.findByEmailIgnoreCase("tenant.admin@localhost")).thenReturn(Optional.empty());
        when(userRepository.findByExternalSubject("tenant.admin@localhost")).thenReturn(Optional.of(user));
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(membershipRepository.findFirstByUserExternalSubjectAndTenantIdAndStatus(
                "tenant.admin@localhost",
                tenant.getId(),
                "ACTIVE"
        )).thenReturn(Optional.empty());
        when(membershipRepository.save(any(TenantMembership.class))).thenAnswer(invocation -> invocation.getArgument(0));

        LocalCredentialAuthService service = new LocalCredentialAuthService(
                userRepository,
                tenantRepository,
                membershipRepository,
                authTokenService(),
                tenantSupportGrantService,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                auditEventService,
                false,
                true,
                "",
                "",
                "http://localhost:5173,http://127.0.0.1:5173"
        );

        AuthTokenResponse response = service.login("tenant.admin@localhost", "LocalDevTenant123!");
        Jwt jwt = decode(response.token());

        assertEquals("tenant.admin@localhost", jwt.getSubject());
        assertEquals(tenant.getId().toString(), jwt.getClaimAsString("active_tenant_id"));
        assertEquals("TENANT_ADMIN", jwt.getClaimAsStringList("roles").get(0));
        assertTrue(BCrypt.checkpw("LocalDevTenant123!", user.getPasswordHash()));
        verify(membershipRepository).save(any(TenantMembership.class));
    }

    @Test
    void realTenantAdminLoginWinsOverSharedLocalhostFallback() {
        AppUser user = new AppUser();
        user.setExternalSubject("tenant.admin@localhost");
        user.setEmail("tenant.admin@localhost");
        user.setPasswordHash(BCrypt.hashpw("gm-test-password", BCrypt.gensalt(10)));

        Tenant tenant = tenant("GM Test");
        TenantMembership membership = membership(user, tenant, "TENANT_ADMIN");

        when(userRepository.findByEmailIgnoreCase("tenant.admin@localhost")).thenReturn(Optional.of(user));
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(membershipRepository.findByUserExternalSubjectAndStatusOrderByCreatedAtAsc("tenant.admin@localhost", "ACTIVE"))
                .thenReturn(List.of(membership));

        LocalCredentialAuthService service = new LocalCredentialAuthService(
                userRepository,
                tenantRepository,
                membershipRepository,
                authTokenService(),
                tenantSupportGrantService,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                auditEventService,
                false,
                true,
                "",
                "",
                "http://localhost:5173,http://127.0.0.1:5173"
        );

        AuthTokenResponse response = service.login("tenant.admin@localhost", "gm-test-password");
        Jwt jwt = decode(response.token());

        assertEquals(tenant.getId().toString(), jwt.getClaimAsString("active_tenant_id"));
        verifyNoInteractions(tenantRepository);
    }

    private AuthTokenService authTokenService() {
        return new AuthTokenService(SECRET, 60, "active_tenant_id");
    }

    private Jwt decode(String token) {
        return NimbusJwtDecoder
                .withSecretKey(new SecretKeySpec(SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256"))
                .build()
                .decode(token);
    }

    private Tenant tenant(String name) {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName(name);
        return tenant;
    }

    private TenantMembership membership(AppUser user, Tenant tenant, String role) {
        TenantMembership membership = new TenantMembership();
        membership.setTenant(tenant);
        membership.setUser(user);
        membership.setRole(role);
        membership.setStatus("ACTIVE");
        return membership;
    }

    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }
}
