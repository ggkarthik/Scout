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
        Integer sbomRateLimitWindowSeconds,
        Integer maxSbomJobsPerRateLimitWindow,
        Integer maxActiveSbomJobs,
        Instant demoExpiresAt,
        Instant expiredAt,
        Instant purgeStartedAt,
        Instant purgedAt,
        String purgeStatus,
        String purgeError,
        String demoCreatedBy,
        String demoSource,
        String demoOwnerEmail,
        boolean demoDataRequested,
        String demoDataStatus,
        String demoDataVersion,
        Instant demoDataSeededAt,
        String demoDataError,
        Instant createdAt,
        Instant updatedAt
) {
}
