package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.TenantQuotaUpdateRequest;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class TenantAdministrationService {

    private final TenantService tenantService;
    private final DemoTenantPurgeService demoTenantPurgeService;
    private final TenantSchemaMigrationService tenantSchemaMigrationService;
    private final IdentityAdministrationService identityAdministrationService;
    private final boolean synchronousTenantProvisioningEnabled;

    public TenantAdministrationService(
            TenantService tenantService,
            DemoTenantPurgeService demoTenantPurgeService,
            TenantSchemaMigrationService tenantSchemaMigrationService,
            IdentityAdministrationService identityAdministrationService,
            @Value("${app.demo.synchronous-tenant-provisioning-enabled:false}") boolean synchronousTenantProvisioningEnabled
    ) {
        this.tenantService = tenantService;
        this.demoTenantPurgeService = demoTenantPurgeService;
        this.tenantSchemaMigrationService = tenantSchemaMigrationService;
        this.identityAdministrationService = identityAdministrationService;
        this.synchronousTenantProvisioningEnabled = synchronousTenantProvisioningEnabled;
    }

    public List<Tenant> listTenants() {
        return tenantService.listTenants();
    }

    public Tenant getTenant(UUID tenantId) {
        return tenantService.requireTenantUuid(tenantId);
    }

    public Tenant createTenant(String name, String slug, String planCode, String billingRef, boolean addDemoData) {
        return createTenant(name, slug, planCode, billingRef, addDemoData, null, null);
    }

    public Tenant createTenant(
            String name,
            String slug,
            String planCode,
            String billingRef,
            boolean addDemoData,
            String ownerEmail,
            String ownerPassword
    ) {
        boolean hasOwnerEmail = ownerEmail != null && !ownerEmail.isBlank();
        boolean hasOwnerPassword = ownerPassword != null && !ownerPassword.isBlank();
        if (hasOwnerEmail != hasOwnerPassword) {
            throw new IllegalArgumentException("Owner email and owner password must be provided together");
        }
        if ((hasOwnerEmail || hasOwnerPassword) && !synchronousTenantProvisioningEnabled) {
            throw new IllegalArgumentException(
                    "Direct demo credentials require synchronous provisioning; use the invite flow in production");
        }
        Tenant tenant = tenantService.createTenant(name, slug, planCode, billingRef, addDemoData);
        if (synchronousTenantProvisioningEnabled) {
            tenantSchemaMigrationService.provisionNewTenant(tenant);
        }
        if (hasOwnerEmail) {
            identityAdministrationService.provisionTenantOwner(
                    tenant.getId(), ownerEmail, ownerPassword, ownerEmail);
        }
        return tenant;
    }

    public Tenant retryProvisioning(UUID tenantId) {
        return tenantService.retryProvisioning(tenantId);
    }

    public Tenant updateStatus(UUID tenantId, String status) {
        return tenantService.updateStatus(tenantId, status);
    }

    public Tenant extendDemoExpiry(UUID tenantId, Instant expiresAt) {
        return tenantService.extendDemoExpiry(tenantId, expiresAt);
    }

    public Tenant updateQuotas(UUID tenantId, TenantQuotaUpdateRequest request) {
        return tenantService.updateQuotas(tenantId, request);
    }

    public void deleteTenant(UUID tenantId) {
        demoTenantPurgeService.deleteTenant(tenantId, Instant.now());
    }
}
