package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class TenantUserInviteServiceTest {

    @Mock
    private IdentityAdministrationService identityAdministrationService;
    @Mock
    private TenantInviteEmailService tenantInviteEmailService;
    @Mock
    private LocalCredentialAuthService localCredentialAuthService;
    @Mock
    private AppUserRepository appUserRepository;
    @Mock
    private TenantRepository tenantRepository;
    @Mock
    private AuditEventService auditEventService;

    @Test
    void createInviteRejectsUserWithAnotherActiveTenantMembership() {
        UUID requestedTenantId = UUID.randomUUID();
        when(tenantRepository.findById(requestedTenantId)).thenReturn(Optional.of(tenant(requestedTenantId, "Requested")));
        doThrow(new ResponseStatusException(org.springframework.http.HttpStatus.CONFLICT,
                "This user already has active access to another tenant"))
                .when(identityAdministrationService)
                .loadOrCreateEligibleLockedUser(
                        eq(requestedTenantId),
                        eq("customer@example.com"),
                        eq("customer@example.com"),
                        eq("Customer"));

        TenantUserInviteService service = new TenantUserInviteService(
                identityAdministrationService,
                tenantInviteEmailService,
                localCredentialAuthService,
                appUserRepository,
                tenantRepository,
                auditEventService
        );

        ResponseStatusException error = assertThrows(
                ResponseStatusException.class,
                () -> service.createInvite(requestedTenantId, "customer@example.com", "Customer", "TENANT_ADMIN", "inviter@example.com")
        );

        assertEquals(409, error.getStatusCode().value());
        assertEquals("This user already has active access to another tenant", error.getReason());
    }

    private Tenant tenant(UUID id, String name) {
        Tenant tenant = new Tenant();
        tenant.setId(id);
        tenant.setName(name);
        tenant.setStatus("ACTIVE");
        return tenant;
    }

}
