package com.prototype.vulnwatch.service;

import java.util.Set;
import java.time.Instant;
import java.util.UUID;

public record AuthenticatedTenantActor(
        String subject,
        UUID userId,
        String email,
        String displayName,
        UUID tenantId,
        String tenantName,
        String tenantSchemaName,
        Set<String> roles,
        TenantAccessMode accessMode,
        UUID accessReferenceId,
        Instant accessExpiresAt
) {
    public AuthenticatedTenantActor(
            String subject, UUID userId, String email, String displayName, UUID tenantId,
            String tenantName, String tenantSchemaName, Set<String> roles
    ) {
        this(subject, userId, email, displayName, tenantId, tenantName, tenantSchemaName, roles, null, null, null);
    }
}
