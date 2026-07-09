package com.prototype.vulnwatch.dto;

public record PerformanceSloScorecardItemResponse(
        String key,
        String label,
        String unit,
        double targetValue,
        double currentValue,
        boolean compliant,
        String window
) {
}
