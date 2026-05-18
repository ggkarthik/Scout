package com.prototype.vulnwatch.service;

import static org.springframework.http.HttpStatus.FORBIDDEN;

import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class TenantAccessControlService {

    private final TenantSupportGrantService tenantSupportGrantService;

    public TenantAccessControlService(TenantSupportGrantService tenantSupportGrantService) {
        this.tenantSupportGrantService = tenantSupportGrantService;
    }

    public void assertTenantAccess(RequestActor actor, UUID tenantId) {
        if (tenantId == null) {
            throw new ResponseStatusException(FORBIDDEN, "Tenant context is required");
        }
        if (actor == null) {
            throw new ResponseStatusException(FORBIDDEN, "Authenticated actor is required");
        }
        if (actor.hasRole("PLATFORM_OWNER")) {
            if (actor.tenantId() == null || !actor.tenantId().equals(tenantId)) {
                throw new ResponseStatusException(FORBIDDEN, "Platform owner must switch into the approved tenant context first");
            }
            tenantSupportGrantService.requireActiveGrant(actor.userId(), tenantId);
            return;
        }
        if (actor.tenantId() == null || !actor.tenantId().equals(tenantId)) {
            throw new ResponseStatusException(FORBIDDEN, "Cannot access another tenant");
        }
    }
}
