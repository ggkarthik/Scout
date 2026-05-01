package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
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
