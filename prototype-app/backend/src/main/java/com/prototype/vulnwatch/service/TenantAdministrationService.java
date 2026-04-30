package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;

@Service
public class TenantAdministrationService {

    private final TenantService tenantService;

    public TenantAdministrationService(TenantService tenantService) {
        this.tenantService = tenantService;
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
}
