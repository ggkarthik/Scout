package com.prototype.vulnwatch.service;

import java.util.Set;
import java.time.Instant;
import java.util.UUID;

public record RequestActor(
        String userId,
        boolean creator,
        UUID tenantId,
        String tenantName,
        Set<String> roles,
        TenantAccessMode accessMode,
        UUID accessReferenceId,
        Instant accessExpiresAt
) {
    public RequestActor(String userId, boolean creator, UUID tenantId, String tenantName, Set<String> roles) {
        this(userId, creator, tenantId, tenantName, roles, null, null, null);
    }

    public RequestActor(String userId, boolean creator, UUID tenantId, String tenantName) {
        this(userId, creator, tenantId, tenantName, Set.of(), null, null, null);
    }

    public boolean hasRole(String role) {
        return roles != null && roles.contains(role);
    }

    public boolean platformScope() {
        return hasRole("PLATFORM_OWNER") && tenantId == null;
    }

    public boolean actingAsPlatformOwner() {
        return hasRole("PLATFORM_OWNER") && tenantId != null;
    }

    public boolean hasDirectTenantMembership() {
        return accessMode == TenantAccessMode.DIRECT_PLAYGROUND_MEMBERSHIP
                || accessMode == TenantAccessMode.TENANT_MEMBERSHIP;
    }
}
