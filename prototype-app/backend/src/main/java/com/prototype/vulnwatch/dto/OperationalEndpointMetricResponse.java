package com.prototype.vulnwatch.dto;

import java.time.Instant;

public record OperationalEndpointMetricResponse(
        String key,
        String label,
        long requestCount,
        long successCount,
        long errorCount,
        double averageMs,
        double p95Ms,
        double p99Ms,
        long maxMs,
        long lastMs,
        Instant lastRecordedAt
) {
}
