package com.prototype.vulnwatch.dto;

public record OperationalExecutiveHealthResponse(
        double ingestionSuccessRateLast24h,
        double recomputeP95Ms,
        double normalizationCoveragePercent,
        double correlationNoiseReductionPercent,
        long openCriticalFindings
) {
}
