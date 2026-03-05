package com.prototype.vulnwatch.dto;

import java.util.List;

public record DashboardResponse(
        long assets,
        long components,
        long openFindings,
        long criticalFindings,
        long openCritical,
        long openHigh,
        long openMedium,
        long openLow,
        double averageOpenRiskScore,
        double averageOpenConfidenceScore,
        long highConfidenceOpenFindings,
        List<TopFindingMetricResponse> topVulnerabilities,
        List<TopFindingMetricResponse> topInstalledComponents,
        List<TopFindingMetricResponse> topAssetsAtRisk,
        List<TopFindingMetricResponse> topVulnerabilityProductIdentities,
        List<FindingResponse> latestFindings,
        DashboardNoiseReductionResponse noiseReduction,
        DashboardCsafVexAnalyticsResponse csafVexAnalytics,
        DashboardCorrelationEfficiencyResponse correlationEfficiency
) {
}
