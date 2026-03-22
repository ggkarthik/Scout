package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;

public record OperationalApiReadPathResponse(
        boolean summaryReadModelReady,
        long canonicalCveCount,
        long summaryCveCount,
        double summaryCoveragePercent,
        boolean noiseProjectionReady,
        Instant noiseProjectionLastComputedAt,
        Long noiseProjectionAgeSeconds,
        double noiseProjectionRefreshP95Ms,
        long noiseProjectionRefreshFailures,
        boolean filterCacheActive,
        Instant filterCacheExpiresAt,
        long filterCacheHits,
        long filterCacheMisses,
        double filterCacheHitRatioPercent,
        List<OperationalEndpointMetricResponse> endpointMetrics
) {
}
