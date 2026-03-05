package com.prototype.vulnwatch.dto;

import java.util.List;

public record OperationalFreshnessDriftResponse(
        long staleThresholdHours,
        long staleSourceCount,
        double normalizationCoverageDrift7d,
        double cpeFallbackShareDrift7d,
        List<OperationalSourceFreshnessResponse> sourceFreshness
) {
}
