package com.prototype.vulnwatch.dto;

import java.util.List;

public record DashboardCsafVexAnalyticsResponse(
        long csafRunsLast30Days,
        long csafSuccessfulRunsLast30Days,
        long csafPartialFailureRunsLast30Days,
        double csafNormalizationSuccessRate,
        double csafPartialFailureRate,
        long findingsSuppressedByVex,
        long suppressedByStaleVex,
        long underInvestigationAging,
        List<TopFindingMetricResponse> vexCoverageByProvider,
        List<TopFindingMetricResponse> staleSuppressionsTrendLast30Days
) {
}
