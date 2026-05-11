package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantMembership;
import com.prototype.vulnwatch.dto.AuthSessionResponse;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class ValidationAuthServiceTest {

    private static final String SECRET = "phase-1-validation-auth-secret-32-bytes";

    @Mock
    AppUserRepository appUserRepository;

    @Mock
    TenantMembershipRepository membershipRepository;

    @Test
    void loginReturnsBearerTokenForTenantMember() {
        AppUser user = new AppUser();
        user.setExternalSubject("alex@example.com");
        user.setEmail("alex@example.com");
        user.setDisplayName("Alex Rivera");
        user.setPasswordHash(new BCryptPasswordEncoder().encode("correct horse battery"));

        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Example Co");
        tenant.setSlug("example-co");

        TenantMembership membership = new TenantMembership();
        membership.setTenant(tenant);
        membership.setRole("TENANT_ADMIN");

        when(appUserRepository.findByEmailIgnoreCase("alex@example.com")).thenReturn(Optional.of(user));
        when(membershipRepository.findByUserExternalSubjectAndStatusOrderByCreatedAtAsc("alex@example.com", "ACTIVE"))
                .thenReturn(List.of(membership));

        ValidationAuthService service = new ValidationAuthService(
                appUserRepository,
                membershipRepository,
                new BCryptPasswordEncoder(),
                SECRET,
                12);

        AuthSessionResponse response = service.login("alex@example.com", "correct horse battery");

        assertEquals("Bearer", response.tokenType());
        assertNotNull(response.expiresAt());
        var decoder = NimbusJwtDecoder
                .withSecretKey(new SecretKeySpec(SECRET.getBytes(java.nio.charset.StandardCharsets.UTF_8), "HmacSHA256"))
                .build();
        var jwt = decoder.decode(response.token());
        assertEquals("alex@example.com", jwt.getSubject());
        assertEquals(tenant.getId().toString(), jwt.getClaimAsString("tenant_id"));
    }

    @Test
    void loginRejectsWrongPassword() {
        AppUser user = new AppUser();
        user.setExternalSubject("alex@example.com");
        user.setEmail("alex@example.com");
        user.setPasswordHash(new BCryptPasswordEncoder().encode("correct horse battery"));

        when(appUserRepository.findByEmailIgnoreCase("alex@example.com")).thenReturn(Optional.of(user));

        ValidationAuthService service = new ValidationAuthService(
                appUserRepository,
                membershipRepository,
                new BCryptPasswordEncoder(),
                SECRET,
                12);

        assertThrows(ResponseStatusException.class, () -> service.login("alex@example.com", "wrong password"));
    }

    @Test
    void issueSessionAllowsPlatformOwnerWithoutTenant() {
        AppUser user = new AppUser();
        user.setExternalSubject("owner@example.com");
        user.setEmail("owner@example.com");
        user.setPlatformOwner(true);

        ValidationAuthService service = new ValidationAuthService(
                appUserRepository,
                membershipRepository,
                new BCryptPasswordEncoder(),
                SECRET,
                12);

        AuthSessionResponse response = service.issueSession(user);

        var decoder = NimbusJwtDecoder
                .withSecretKey(new SecretKeySpec(SECRET.getBytes(java.nio.charset.StandardCharsets.UTF_8), "HmacSHA256"))
                .build();
        var jwt = decoder.decode(response.token());
        assertEquals("owner@example.com", jwt.getSubject());
        assertEquals("PLATFORM_OWNER", jwt.getClaimAsStringList("roles").get(0));
    }

    @Test
    void issueSessionKeepsPlatformOwnerTenantlessEvenWithActiveMembership() {
        AppUser user = new AppUser();
        user.setExternalSubject("owner@example.com");
        user.setEmail("owner@example.com");
        user.setPlatformOwner(true);

        ValidationAuthService service = new ValidationAuthService(
                appUserRepository,
                membershipRepository,
                new BCryptPasswordEncoder(),
                SECRET,
                12);

        AuthSessionResponse response = service.issueSession(user);

        var decoder = NimbusJwtDecoder
                .withSecretKey(new SecretKeySpec(SECRET.getBytes(java.nio.charset.StandardCharsets.UTF_8), "HmacSHA256"))
                .build();
        var jwt = decoder.decode(response.token());
        assertEquals("owner@example.com", jwt.getSubject());
        assertEquals(List.of("PLATFORM_OWNER"), jwt.getClaimAsStringList("roles"));
        assertNull(jwt.getClaimAsString("tenant_id"));
        assertNull(jwt.getClaimAsString("tenant_slug"));
    }
}
