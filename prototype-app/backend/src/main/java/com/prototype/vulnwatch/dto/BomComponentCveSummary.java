package com.prototype.vulnwatch.dto;

public record BomComponentCveSummary(
        String cveId,
        String externalId,
        String severity,
        String title,
        String applicabilityState,
        Double epssScore,
        Double cvssScore
) {}
