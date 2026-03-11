package com.prototype.vulnwatch.dto;

public record OperationalNormalizationQualityResponse(
        long activeComponents,
        double normalizedNameCoveragePercent,
        double normalizedVersionCoveragePercent,
        double softwareIdentityCoveragePercent
) {
}
