package com.prototype.vulnwatch.dto;

import java.util.List;

public record OperationalNoiseLifecycleResponse(
        long totalFilteredNotApplicable,
        long neverOpenedNotApplicable,
        long autoResolvedNotApplicable,
        long deferredUnderInvestigation,
        double filteredPercentOfPotential,
        double reopenRatePercent,
        List<TopFindingMetricResponse> notApplicableCategories
) {
}
