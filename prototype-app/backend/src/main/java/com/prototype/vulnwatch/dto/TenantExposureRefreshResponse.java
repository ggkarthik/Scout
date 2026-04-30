package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record TenantExposureRefreshResponse(
        UUID tenantId,
        String status,
        String message,
        OrgSpecificCveExposureRecomputeResponse refresh,
        Instant refreshedAt
) {
}
