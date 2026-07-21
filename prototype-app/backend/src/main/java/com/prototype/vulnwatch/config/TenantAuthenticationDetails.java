package com.prototype.vulnwatch.config;

import java.util.Set;
import java.time.Instant;
import java.util.UUID;
import com.prototype.vulnwatch.service.TenantAccessMode;

public record TenantAuthenticationDetails(
        UUID tenantId,
        String tenantName,
        String userId,
        String email,
        String displayName,
        Set<String> roles,
        TenantAccessMode accessMode,
        UUID accessReferenceId,
        Instant accessExpiresAt
) {
    public TenantAuthenticationDetails(
            UUID tenantId, String tenantName, String userId, String email, String displayName, Set<String> roles
    ) {
        this(tenantId, tenantName, userId, email, displayName, roles, null, null, null);
    }
}
