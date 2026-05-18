package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import java.time.Instant;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class TenantLifecycleGuardService {

    public boolean isDemoTenant(Tenant tenant) {
        return tenant != null && DemoLifecycleService.DEMO_PLAN_CODE.equalsIgnoreCase(tenant.getPlanCode());
    }

    public boolean isExpiredDemoTenant(Tenant tenant) {
        return isDemoTenant(tenant)
                && tenant.getDemoExpiresAt() != null
                && !tenant.getDemoExpiresAt().isAfter(Instant.now());
    }

    public boolean isTenantAccessible(Tenant tenant) {
        if (tenant == null) {
            return false;
        }
        String status = tenant.getStatus();
        if ("DELETED".equalsIgnoreCase(status) || "PURGING".equalsIgnoreCase(status)) {
            return false;
        }
        if (isExpiredDemoTenant(tenant)) {
            return false;
        }
        return !"EXPIRED".equalsIgnoreCase(status);
    }

    public void assertTenantAccessible(Tenant tenant) {
        if (tenant == null) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Tenant context is required");
        }
        if ("DELETED".equalsIgnoreCase(tenant.getStatus())) {
            throw new ResponseStatusException(HttpStatus.GONE, "This tenant has been deleted and is no longer available");
        }
        if ("PURGING".equalsIgnoreCase(tenant.getStatus())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "This tenant has expired and is being purged");
        }
        if ("EXPIRED".equalsIgnoreCase(tenant.getStatus()) || isExpiredDemoTenant(tenant)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "This demo tenant has expired and is no longer accessible");
        }
    }
}
