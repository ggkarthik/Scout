package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantMembership;
import com.prototype.vulnwatch.domain.TenantSupportGrant;
import com.prototype.vulnwatch.dto.AllowedTenantResponse;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class AllowedTenantContextServiceTest {

    @Mock
    private TenantMembershipRepository tenantMembershipRepository;
    @Mock
    private TenantLifecycleGuardService tenantLifecycleGuardService;
    @Mock
    private TenantSupportGrantService tenantSupportGrantService;

    @Test
    void tenantScopedUsersSurfaceTheirSingleAccessibleTenantMembership() {
        Tenant firstTenant = tenant("Customer A", "customer-a");
        TenantMembership firstMembership = membership(firstTenant, "TENANT_ADMIN");
        RequestActor actor = new RequestActor(
                "tenant.admin@example.com",
                false,
                firstTenant.getId(),
                firstTenant.getName(),
                Set.of("TENANT_ADMIN")
        );

        when(tenantMembershipRepository.findByUserExternalSubjectAndStatusOrderByCreatedAtAsc(
                actor.userId(),
                "ACTIVE"
        )).thenReturn(List.of(firstMembership));
        when(tenantLifecycleGuardService.isTenantAccessible(firstTenant)).thenReturn(true);

        AllowedTenantContextService service = new AllowedTenantContextService(
                tenantMembershipRepository,
                tenantLifecycleGuardService,
                tenantSupportGrantService
        );

        List<AllowedTenantResponse> allowed = service.listAllowedTenants(actor);

        assertEquals(1, allowed.size());
        assertEquals(firstTenant.getId().toString(), allowed.get(0).id());
        assertEquals("Customer A", allowed.get(0).name());
        assertEquals("customer-a", allowed.get(0).slug());
        assertEquals("TENANT_ADMIN", allowed.get(0).role());
        assertNull(allowed.get(0).accessMode());
        assertNull(allowed.get(0).expiresAt());
    }

    @Test
    void tenantScopedUsersReceiveConflictWhenMultipleAccessibleMembershipsExist() {
        Tenant firstTenant = tenant("Customer A", "customer-a");
        Tenant secondTenant = tenant("Customer B", "customer-b");
        TenantMembership firstMembership = membership(firstTenant, "TENANT_ADMIN");
        TenantMembership secondMembership = membership(secondTenant, "SECURITY_ANALYST");
        RequestActor actor = new RequestActor(
                "tenant.admin@example.com",
                false,
                firstTenant.getId(),
                firstTenant.getName(),
                Set.of("TENANT_ADMIN")
        );

        when(tenantMembershipRepository.findByUserExternalSubjectAndStatusOrderByCreatedAtAsc(
                actor.userId(),
                "ACTIVE"
        )).thenReturn(List.of(firstMembership, secondMembership));
        when(tenantLifecycleGuardService.isTenantAccessible(firstTenant)).thenReturn(true);
        when(tenantLifecycleGuardService.isTenantAccessible(secondTenant)).thenReturn(true);

        AllowedTenantContextService service = new AllowedTenantContextService(
                tenantMembershipRepository,
                tenantLifecycleGuardService,
                tenantSupportGrantService
        );

        ResponseStatusException conflict = assertThrows(ResponseStatusException.class, () -> service.listAllowedTenants(actor));

        assertEquals(409, conflict.getStatusCode().value());
    }

    @Test
    void platformOwnersSurfacePlaygroundMembershipsAndActiveSupportGrantsSortedByName() {
        Tenant zuluTenant = tenant("Zulu Labs", "zulu");
        Tenant alphaTenant = tenant("Alpha Labs", "alpha");
        Tenant playgroundTenant = tenant("Default Workspace", "default-workspace");
        TenantSupportGrant zuluGrant = supportGrant(zuluTenant, "WRITE", Instant.parse("2026-08-01T00:00:00Z"));
        TenantSupportGrant alphaGrant = supportGrant(alphaTenant, "READ_ONLY", Instant.parse("2026-07-20T00:00:00Z"));
        TenantMembership playgroundMembership = membership(playgroundTenant, "TENANT_ADMIN");
        RequestActor actor = new RequestActor(
                "owner@example.com",
                true,
                null,
                null,
                Set.of("PLATFORM_OWNER")
        );

        when(tenantMembershipRepository.findByUserExternalSubjectAndStatusOrderByCreatedAtAsc(
                actor.userId(),
                "ACTIVE"
        )).thenReturn(List.of(playgroundMembership));
        when(tenantLifecycleGuardService.isTenantAccessible(playgroundTenant)).thenReturn(true);
        when(tenantLifecycleGuardService.isTenantAccessible(zuluTenant)).thenReturn(true);
        when(tenantLifecycleGuardService.isTenantAccessible(alphaTenant)).thenReturn(true);
        when(tenantSupportGrantService.listActiveGrantsForPlatformOwner(actor.userId()))
                .thenReturn(List.of(zuluGrant, alphaGrant));

        AllowedTenantContextService service = new AllowedTenantContextService(
                tenantMembershipRepository,
                tenantLifecycleGuardService,
                tenantSupportGrantService
        );

        List<AllowedTenantResponse> allowed = service.listAllowedTenants(actor);

        assertEquals(3, allowed.size());
        assertEquals("Alpha Labs", allowed.get(0).name());
        assertEquals("PLATFORM_OWNER", allowed.get(0).role());
        assertEquals("READ_ONLY", allowed.get(0).accessMode());
        assertEquals(Instant.parse("2026-07-20T00:00:00Z"), allowed.get(0).expiresAt());
        assertEquals("Default Workspace", allowed.get(1).name());
        assertEquals("TENANT_ADMIN", allowed.get(1).role());
        assertNull(allowed.get(1).accessMode());
        assertNull(allowed.get(1).expiresAt());
        assertEquals("Zulu Labs", allowed.get(2).name());
        assertEquals("PLATFORM_OWNER", allowed.get(2).role());
        assertEquals("WRITE", allowed.get(2).accessMode());
        assertEquals(Instant.parse("2026-08-01T00:00:00Z"), allowed.get(2).expiresAt());
    }

    private Tenant tenant(String name, String slug) {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName(name);
        tenant.setSlug(slug);
        tenant.setStatus("ACTIVE");
        return tenant;
    }

    private TenantMembership membership(Tenant tenant, String role) {
        TenantMembership membership = new TenantMembership();
        membership.setTenant(tenant);
        membership.setRole(role);
        membership.setStatus("ACTIVE");
        return membership;
    }

    private TenantSupportGrant supportGrant(Tenant tenant, String accessMode, Instant expiresAt) {
        TenantSupportGrant grant = new TenantSupportGrant();
        grant.setTenant(tenant);
        grant.setAccessMode(accessMode);
        grant.setExpiresAt(expiresAt);
        grant.setStatus("ACCEPTED");
        return grant;
    }
}
