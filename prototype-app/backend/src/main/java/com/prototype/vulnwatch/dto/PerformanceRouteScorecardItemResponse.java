package com.prototype.vulnwatch.dto;

public record PerformanceRouteScorecardItemResponse(
        String key,
        String label,
        String path,
        String category,
        String status,
        String unit,
        double targetP95Ms,
        double targetP99Ms,
        long requestCount,
        double currentP95Ms,
        double currentP99Ms,
        boolean compliant,
        String note
) {
}
