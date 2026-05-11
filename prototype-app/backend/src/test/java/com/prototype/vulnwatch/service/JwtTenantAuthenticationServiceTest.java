package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.jwt.Jwt;

@ExtendWith(MockitoExtension.class)
class JwtTenantAuthenticationServiceTest {

    @Mock
    AppUserRepository userRepository;

    @Mock
    TenantRepository tenantRepository;

    @Mock
    TenantMembershipRepository membershipRepository;

    @Test
    void platformOwnerJwtWithoutExplicitTenantStaysTenantless() {
        AppUser user = new AppUser();
        user.setExternalSubject("owner@example.com");

        when(userRepository.findByExternalSubject("owner@example.com")).thenReturn(Optional.of(user));
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));

        JwtTenantAuthenticationService service = new JwtTenantAuthenticationService(
                userRepository,
                tenantRepository,
                membershipRepository,
                "tenant_id",
                "tenant_slug",
                "email",
                "name",
                "roles");

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
}
