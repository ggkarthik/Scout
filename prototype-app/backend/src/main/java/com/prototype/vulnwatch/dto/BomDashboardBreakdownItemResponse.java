package com.prototype.vulnwatch.dto;

public record BomDashboardBreakdownItemResponse(
        String key,
        String label,
        long count
) {}
