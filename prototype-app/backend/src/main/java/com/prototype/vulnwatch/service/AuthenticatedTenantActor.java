package com.prototype.vulnwatch.service;

import java.util.Set;
import java.util.UUID;

public record AuthenticatedTenantActor(
        String subject,
        UUID userId,
        String email,
        String displayName,
        UUID tenantId,
        String tenantName,
        String tenantSchemaName,
        Set<String> roles
) {
}
