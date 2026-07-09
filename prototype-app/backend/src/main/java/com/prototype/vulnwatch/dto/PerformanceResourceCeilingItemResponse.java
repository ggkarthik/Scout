package com.prototype.vulnwatch.dto;

public record PerformanceResourceCeilingItemResponse(
        String key,
        String label,
        String category,
        String status,
        String unit,
        double targetValue,
        double currentValue,
        boolean compliant,
        String note
) {
}
