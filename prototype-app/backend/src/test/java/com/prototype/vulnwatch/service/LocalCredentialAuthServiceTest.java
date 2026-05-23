package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
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

    @Test
    void platformOwnerLoginReturnsPlatformScopeToken() {
        AppUser existingUser = new AppUser();
        existingUser.setExternalSubject("owner@example.com");
        existingUser.setEmail("owner@example.com");

        when(userRepository.findByExternalSubject("owner@example.com")).thenReturn(Optional.of(existingUser));
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));

        LocalCredentialAuthService service = new LocalCredentialAuthService(
                userRepository,
                tenantRepository,
                membershipRepository,
                authTokenService(),
                tenantSupportGrantService,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                "owner@example.com",
                BCrypt.hashpw("password-123", BCrypt.gensalt(10))
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
                "owner@example.com",
                BCrypt.hashpw("platform-password", BCrypt.gensalt(10))
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
                "owner@example.com",
                BCrypt.hashpw("platform-password", BCrypt.gensalt(10))
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
