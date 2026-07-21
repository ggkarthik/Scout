package com.prototype.vulnwatch.service;

import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import static org.springframework.http.HttpStatus.FORBIDDEN;

@Service
public class TenantAccessControlService {

    public TenantAccessControlService() {
    }

    public void assertTenantAccess(RequestActor actor, UUID tenantId) {
        if (tenantId == null) {
            throw new ResponseStatusException(FORBIDDEN, "Tenant context is required");
        }
        if (actor == null) {
            throw new ResponseStatusException(FORBIDDEN, "Authenticated actor is required");
        }
        if (actor.tenantId() == null || !actor.tenantId().equals(tenantId)) {
            throw new ResponseStatusException(FORBIDDEN, "Cannot access another tenant");
        }
        if (actor.accessMode() == null) {
            throw new ResponseStatusException(FORBIDDEN, "Resolved tenant authorization is required");
        }
        if (actor.hasRole("PLATFORM_OWNER") && !actor.hasDirectTenantMembership()) {
            throw new ResponseStatusException(FORBIDDEN,
                    "Support access does not grant tenant-administration membership");
        }
    }
}
