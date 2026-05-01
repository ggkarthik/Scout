package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantMembership;
import com.prototype.vulnwatch.dto.TestPersonaTokenResponse;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.util.Optional;
import java.util.UUID;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class TestPersonaServiceTest {

    private static final String SECRET = "phase-1-test-personas-secret-32-bytes";

    @Mock
    TenantRepository tenantRepository;
    @Mock
    AppUserRepository userRepository;
    @Mock
    TenantMembershipRepository membershipRepository;

    @Test
    void disabledPersonasReturnNotFound() {
        TestPersonaService service = new TestPersonaService(
                tenantRepository,
                userRepository,
                membershipRepository,
                false,
                SECRET,
                60);

        assertThrows(ResponseStatusException.class, service::listPersonas);
    }

    @Test
    void listPersonasReturnsConfiguredPhaseOnePersonas() {
        TestPersonaService service = new TestPersonaService(
                tenantRepository,
                userRepository,
                membershipRepository,
                true,
                SECRET,
                60);

        var personas = service.listPersonas();

        assertEquals(6, personas.size());
        assertEquals("platform-owner", personas.get(0).key());
        assertEquals("Tenant A Admin", personas.get(1).label());
        assertEquals("customer-b", personas.get(2).tenantSlug());
        assertEquals("READ_ONLY_AUDITOR", personas.get(5).roles().iterator().next());
    }

    @Test
    void tenantPersonaTokenContainsExpectedClaimsAndCanBeDecoded() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Customer A");
        tenant.setSlug("customer-a");
        AppUser user = new AppUser();
        user.setExternalSubject("persona-tenant-a-admin");

        when(tenantRepository.findBySlugIgnoreCase("customer-a")).thenReturn(Optional.of(tenant));
        when(userRepository.findByExternalSubject("persona-tenant-a-admin")).thenReturn(Optional.of(user));
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(membershipRepository.findFirstByUserExternalSubjectAndTenantIdAndStatus(
                "persona-tenant-a-admin",
                tenant.getId(),
                "ACTIVE"
        )).thenReturn(Optional.empty());
        when(membershipRepository.save(any(TenantMembership.class))).thenAnswer(invocation -> invocation.getArgument(0));

        TestPersonaService service = new TestPersonaService(
                tenantRepository,
                userRepository,
                membershipRepository,
                true,
                SECRET,
                60);

        TestPersonaTokenResponse response = service.issueToken("tenant-a-admin");
        var decoder = NimbusJwtDecoder
                .withSecretKey(new SecretKeySpec(SECRET.getBytes(java.nio.charset.StandardCharsets.UTF_8), "HmacSHA256"))
                .build();
        var jwt = decoder.decode(response.token());

        assertNotNull(response.expiresAt());
        assertEquals("Tenant A Admin", response.persona().label());
        assertEquals("persona-tenant-a-admin", jwt.getSubject());
        assertEquals(tenant.getId().toString(), jwt.getClaimAsString("tenant_id"));
        assertEquals("customer-a", jwt.getClaimAsString("tenant_slug"));
        assertEquals("TENANT_ADMIN", jwt.getClaimAsStringList("roles").get(0));
    }

    @Test
    void platformOwnerTokenOmitsTenantClaimsAndMembership() {
        AppUser user = new AppUser();
        user.setExternalSubject("persona-platform-owner");

        when(userRepository.findByExternalSubject("persona-platform-owner")).thenReturn(Optional.of(user));
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));

        TestPersonaService service = new TestPersonaService(
                tenantRepository,
                userRepository,
                membershipRepository,
                true,
                SECRET,
                60);

        TestPersonaTokenResponse response = service.issueToken("platform-owner");
        var decoder = NimbusJwtDecoder
                .withSecretKey(new SecretKeySpec(SECRET.getBytes(java.nio.charset.StandardCharsets.UTF_8), "HmacSHA256"))
                .build();
        var jwt = decoder.decode(response.token());

        assertEquals("Platform Owner", response.persona().label());
        assertEquals("persona-platform-owner", jwt.getSubject());
        assertEquals("PLATFORM_OWNER", jwt.getClaimAsStringList("roles").get(0));
        assertNull(jwt.getClaimAsString("tenant_id"));
        assertNull(jwt.getClaimAsString("tenant_slug"));
        verify(tenantRepository, never()).findBySlugIgnoreCase(any());
        verify(membershipRepository, never()).save(any(TenantMembership.class));
    }

    @Test
    void tenantPersonaCreatesMissingTenantUserAndMembership() {
        when(tenantRepository.findBySlugIgnoreCase("customer-a")).thenReturn(Optional.empty());
        when(tenantRepository.save(any(Tenant.class))).thenAnswer(invocation -> {
            Tenant tenant = invocation.getArgument(0);
            tenant.setId(UUID.randomUUID());
            return tenant;
        });
        when(userRepository.findByExternalSubject("persona-tenant-a-security-analyst")).thenReturn(Optional.empty());
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(membershipRepository.findFirstByUserExternalSubjectAndTenantIdAndStatus(
                any(),
                any(),
                any()
        )).thenReturn(Optional.empty());
        when(membershipRepository.save(any(TenantMembership.class))).thenAnswer(invocation -> invocation.getArgument(0));

        TestPersonaService service = new TestPersonaService(
                tenantRepository,
                userRepository,
                membershipRepository,
                true,
                SECRET,
                60);

        TestPersonaTokenResponse response = service.issueToken("tenant-a-security-analyst");

        assertEquals("Customer A", response.persona().tenantName());
        assertEquals("SECURITY_ANALYST", response.persona().roles().iterator().next());
        verify(tenantRepository).save(any(Tenant.class));
        verify(userRepository).save(any(AppUser.class));
        verify(membershipRepository).save(any(TenantMembership.class));
    }

    @Test
    void tenantPersonaUpdatesExistingMembershipRole() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Customer A");
        tenant.setSlug("customer-a");
        AppUser user = new AppUser();
        user.setExternalSubject("persona-tenant-a-inventory-admin");
        TenantMembership membership = new TenantMembership();
        membership.setRole("SECURITY_ANALYST");

        when(tenantRepository.findBySlugIgnoreCase("customer-a")).thenReturn(Optional.of(tenant));
        when(userRepository.findByExternalSubject("persona-tenant-a-inventory-admin")).thenReturn(Optional.of(user));
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(membershipRepository.findFirstByUserExternalSubjectAndTenantIdAndStatus(
                "persona-tenant-a-inventory-admin",
                tenant.getId(),
                "ACTIVE"
        )).thenReturn(Optional.of(membership));
        when(membershipRepository.save(any(TenantMembership.class))).thenAnswer(invocation -> invocation.getArgument(0));

        TestPersonaService service = new TestPersonaService(
                tenantRepository,
                userRepository,
                membershipRepository,
                true,
                SECRET,
                60);

        service.issueToken("tenant-a-inventory-admin");

        assertEquals("INVENTORY_ADMIN", membership.getRole());
        verify(membershipRepository).save(membership);
    }

    @Test
    void unknownPersonaReturnsNotFound() {
        TestPersonaService service = new TestPersonaService(
                tenantRepository,
                userRepository,
                membershipRepository,
                true,
                SECRET,
                60);

        ResponseStatusException error = assertThrows(ResponseStatusException.class, () -> service.issueToken("missing-persona"));
        assertEquals(404, error.getStatusCode().value());
    }

    @Test
    void backendBackedModeRequiresHmacSecret() {
        TestPersonaService service = new TestPersonaService(
                tenantRepository,
                userRepository,
                membershipRepository,
                true,
                "",
                60);

        ResponseStatusException error = assertThrows(ResponseStatusException.class, () -> service.issueToken("platform-owner"));
        assertEquals(409, error.getStatusCode().value());
    }
}
