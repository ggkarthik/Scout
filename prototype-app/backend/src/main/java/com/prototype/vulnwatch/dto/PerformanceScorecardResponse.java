package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;

public record PerformanceScorecardResponse(
        Instant generatedAt,
        String scaleProfile,
        boolean overallCompliant,
        long routeFailureCount,
        long routeNoDataCount,
        long freshnessFailureCount,
        long resourceFailureCount,
        long resourceNoDataCount,
        List<PerformanceRouteScorecardItemResponse> routeItems,
        List<PerformanceSloScorecardItemResponse> freshnessItems,
        List<PerformanceResourceCeilingItemResponse> resourceItems
) {
}
