package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

public record TenantEntitlementOverrideResponse(
        UUID id,
        UUID tenantId,
        String entitlementKey,
        boolean enabled,
        Map<String, Object> config,
        String reason,
        Instant expiresAt,
        UUID createdBy,
        Instant createdAt,
        Instant updatedAt
) {
}
