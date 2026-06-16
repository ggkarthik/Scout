package com.prototype.vulnwatch.dto;

import java.util.List;

public record ApplicationRiskResponse(
        String assetId,
        String assetName,
        String assetIdentifier,
        String businessCriticality,
        List<String> bomTypes,
        int totalComponents,
        int vulnerableComponents,
        int eolComponents,
        int criticalCveCount,
        int highCveCount,
        int mediumCveCount,
        int lowCveCount,
        int totalCveCount,
        double riskScore,
        String riskLevel,
        String lastIngestedAt,
        int findingCount
) {}
