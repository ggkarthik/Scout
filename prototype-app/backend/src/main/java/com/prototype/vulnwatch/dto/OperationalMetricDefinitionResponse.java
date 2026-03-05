package com.prototype.vulnwatch.dto;

public record OperationalMetricDefinitionResponse(
        String section,
        String key,
        String label,
        String description
) {
}
