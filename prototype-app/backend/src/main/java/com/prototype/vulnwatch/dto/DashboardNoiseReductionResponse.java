package com.prototype.vulnwatch.dto;

import java.util.List;

public record DashboardNoiseReductionResponse(
        long totalFilteredNotApplicable,
        long neverOpenedNotApplicable,
        long autoResolvedNotApplicable,
        long deferredUnderInvestigation,
        long potentialFindingsWithoutCorrelation,
        double filteredPercentOfPotential,
        List<TopFindingMetricResponse> categories,
        List<TopFindingMetricResponse> trendLast30Days
) {
}
