package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantEntitlementService;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AiSecurityAccessService {

    private final TenantEntitlementService entitlementService;

    public AiSecurityAccessService(TenantEntitlementService entitlementService) {
        this.entitlementService = entitlementService;
    }

    public void assertEntitled(Tenant tenant) {
        if (tenant == null || !entitlementService.isEnabled(tenant, TenantEntitlementService.AI_SECURITY)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "AI Security is not enabled for this tenant");
        }
    }
}
