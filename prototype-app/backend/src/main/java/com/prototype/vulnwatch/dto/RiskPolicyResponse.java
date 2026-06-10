package com.prototype.vulnwatch.dto;

public record RiskPolicyResponse(
        double criticalThreshold,
        double highThreshold,
        int criticalSlaDays,
        int highSlaDays,
        int mediumSlaDays,
        int lowSlaDays,
        double assetCriticalSlaMultiplier,
        double assetHighSlaMultiplier,
        double assetMediumSlaMultiplier,
        double assetLowSlaMultiplier,
        boolean autoCloseEnabled,
        String autoCloseAssetIdentifier,
        int autoCloseAfterDays,
        String findingGenerationMode,
        String findingsScoreConfig,
        double agentAutoThreshold,
        double agentReviewThreshold,
        int agentMaxConcurrent
) {
}
