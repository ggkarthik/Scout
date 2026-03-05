package com.prototype.vulnwatch.dto;

public record DashboardCorrelationEfficiencyResponse(
        long activeComponents,
        long cpeEligibleActiveComponents,
        long cpeIneligibleActiveComponents,
        double cpeCoveragePercent,
        long openFindingsMatchedByCpe,
        long openFindingsCpeDirect,
        long openFindingsCpeFallback,
        double cpeDirectSharePercent,
        double cpeFallbackSharePercent,
        double averageOpenCpeConfidenceScore,
        long cpeFindingsCreatedLast24Hours,
        long nonCpeFindingsCreatedLast24Hours
) {
}
