package com.prototype.vulnwatch.dto;

public record TenantQuotaUpdateRequest(
        Integer maxConnectorCount,
        Integer maxServiceAccountCount,
        Integer maxDailySbomUploads,
        Integer maxExportRows,
        Integer maxDailyExposureRefreshes,
        Integer sbomRateLimitWindowSeconds,
        Integer maxSbomJobsPerRateLimitWindow,
        Integer maxActiveSbomJobs
) {
}
