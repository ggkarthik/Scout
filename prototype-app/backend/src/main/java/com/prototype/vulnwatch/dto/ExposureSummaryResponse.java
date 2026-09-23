package com.prototype.vulnwatch.dto;

import java.util.List;

public record ExposureSummaryResponse(
        long openFindings,
        long criticalFindings,
        long openCritical,
        long openHigh,
        long openMedium,
        long openLow,
        double averageOpenRiskScore,
        List<TopFindingMetricResponse> topAssetsAtRisk
) {
}
