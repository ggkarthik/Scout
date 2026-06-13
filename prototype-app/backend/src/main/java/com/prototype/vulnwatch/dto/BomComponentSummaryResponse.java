package com.prototype.vulnwatch.dto;

import java.util.List;

public record BomComponentSummaryResponse(
        String componentId,
        String packageName,
        String version,
        String purl,
        String ecosystem,
        String license,
        String assetId,
        String assetName,
        List<String> bomTypes,
        boolean isEol,
        String eolDate,
        int criticalCveCount,
        int highCveCount,
        int mediumCveCount,
        int lowCveCount,
        int totalCveCount,
        String correlationState,
        String riskLevel
) {}
