package com.prototype.vulnwatch.dto;

public record ApplicationCveResponse(
        String vulnerabilityId,
        String componentId,
        String externalId,
        String severity,
        Double cvssScore,
        Double epssScore,
        String packageName,
        String version,
        String lastEvaluatedAt
) {}
