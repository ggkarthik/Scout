package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class TenantAdministrationServiceTest {

    @Mock private TenantService tenantService;
    @Mock private DemoTenantPurgeService demoTenantPurgeService;
    @Mock private TenantSchemaMigrationService tenantSchemaMigrationService;
    @Mock private IdentityAdministrationService identityAdministrationService;

    @Test
    void ownerRecoveryRequiresActiveUnexpiredDemoTenant() {
        UUID tenantId = UUID.randomUUID();
        Tenant tenant = tenant(tenantId, "ACTIVE");
        tenant.setDemoExpiresAt(Instant.now().plusSeconds(3600));
        Tenant saved = tenant(tenantId, "ACTIVE");
        when(tenantService.requireTenantUuid(tenantId)).thenReturn(tenant);
        when(tenantService.updateDemoOwnerEmail(tenantId, "owner@example.com")).thenReturn(saved);

        Tenant result = service().recoverTenantOwner(tenantId, "owner@example.com", "new-password");

        assertEquals(saved, result);
        verify(identityAdministrationService).provisionTenantOwner(tenantId, "owner@example.com", "new-password", "owner@example.com");
        verify(tenantService).updateDemoOwnerEmail(tenantId, "owner@example.com");
    }

    @Test
    void ownerRecoveryRejectsInactiveTenantBeforeChangingCredentials() {
        UUID tenantId = UUID.randomUUID();
        when(tenantService.requireTenantUuid(tenantId)).thenReturn(tenant(tenantId, "SUSPENDED"));

        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> service().recoverTenantOwner(tenantId, "owner@example.com", "new-password"));

        assertEquals("Tenant owner recovery requires an ACTIVE tenant", error.getMessage());
        verifyNoInteractions(identityAdministrationService);
    }

    @Test
    void createTenantProvisionOwnerDoesNotRequireSynchronousSchemaMigration() {
        UUID tenantId = UUID.randomUUID();
        Tenant created = tenant(tenantId, "PROVISIONING");
        Tenant saved = tenant(tenantId, "PROVISIONING");
        when(tenantService.createTenant("Demo", "demo", null, null, false)).thenReturn(created);
        when(tenantService.updateDemoOwnerEmail(tenantId, "owner@example.com")).thenReturn(saved);

        Tenant result = service().createTenant("Demo", "demo", null, null, false,
                "owner@example.com", "new-password");

        assertEquals(saved, result);
        verify(identityAdministrationService).assertOwnerCredentialProvisioningAllowed("owner@example.com");
        verify(identityAdministrationService).provisionTenantOwner(tenantId, "owner@example.com", "new-password", "owner@example.com");
    }

    private TenantAdministrationService service() {
        return new TenantAdministrationService(tenantService, demoTenantPurgeService, tenantSchemaMigrationService,
                identityAdministrationService, false);
    }

    private Tenant tenant(UUID id, String status) {
        Tenant tenant = new Tenant();
        tenant.setId(id);
        tenant.setName("Demo");
        tenant.setStatus(status);
        tenant.setPlanCode("DEMO");
        return tenant;
    }
}
