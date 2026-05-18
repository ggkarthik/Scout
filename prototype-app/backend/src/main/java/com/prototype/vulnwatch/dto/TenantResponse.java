package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record TenantResponse(
        UUID id,
        String name,
        String slug,
        String status,
        String planCode,
        String billingRef,
        Integer maxConnectorCount,
        Integer maxServiceAccountCount,
        Integer maxDailySbomUploads,
        Integer maxExportRows,
        Integer maxDailyExposureRefreshes,
        Instant demoExpiresAt,
        Instant expiredAt,
        Instant purgeStartedAt,
        Instant purgedAt,
        String purgeStatus,
        String purgeError,
        String demoCreatedBy,
        String demoSource,
        Instant createdAt,
        Instant updatedAt
) {
}
