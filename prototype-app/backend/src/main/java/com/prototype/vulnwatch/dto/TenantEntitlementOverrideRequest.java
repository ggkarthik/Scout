package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.Map;

public record TenantEntitlementOverrideRequest(
        boolean enabled,
        Map<String, Object> config,
        String reason,
        Instant expiresAt
) {
}
