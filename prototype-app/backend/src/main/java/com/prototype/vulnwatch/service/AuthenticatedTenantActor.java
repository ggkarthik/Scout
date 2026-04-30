package com.prototype.vulnwatch.service;

import java.util.Set;
import java.util.UUID;

public record AuthenticatedTenantActor(
        String subject,
        UUID userId,
        UUID tenantId,
        String tenantName,
        Set<String> roles
) {
}
