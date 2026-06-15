package com.prototype.vulnwatch.dto;

import java.util.List;
import java.util.UUID;

public record TenantEntitlementSnapshotResponse(
        UUID tenantId,
        String planCode,
        List<TenantEntitlementResponse> entitlements,
        List<TenantEntitlementOverrideResponse> overrides
) {
}
