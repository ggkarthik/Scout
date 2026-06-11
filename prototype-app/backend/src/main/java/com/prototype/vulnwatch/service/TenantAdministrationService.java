package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;

@Service
public class TenantAdministrationService {

    private final TenantService tenantService;
    private final DemoTenantPurgeService demoTenantPurgeService;

    public TenantAdministrationService(TenantService tenantService, DemoTenantPurgeService demoTenantPurgeService) {
        this.tenantService = tenantService;
        this.demoTenantPurgeService = demoTenantPurgeService;
    }

    public List<Tenant> listTenants() {
        return tenantService.listTenants();
    }

    public Tenant createTenant(String name, String slug, String planCode, String billingRef) {
        return tenantService.createTenant(name, slug, planCode, billingRef);
    }

    public Tenant updateStatus(UUID tenantId, String status) {
        return tenantService.updateStatus(tenantId, status);
    }

    public void deleteTenant(UUID tenantId) {
        demoTenantPurgeService.deleteTenant(tenantId, Instant.now());
    }
}
