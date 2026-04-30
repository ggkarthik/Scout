package com.prototype.vulnwatch.config;

import java.util.Set;
import java.util.UUID;

public record TenantAuthenticationDetails(
        UUID tenantId,
        String tenantName,
        String userId,
        Set<String> roles
) {
}
