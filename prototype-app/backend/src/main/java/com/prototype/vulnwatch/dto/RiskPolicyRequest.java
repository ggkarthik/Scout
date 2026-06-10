package com.prototype.vulnwatch.dto;

public record RiskPolicyRequest(
        Double criticalThreshold,
        Double highThreshold,
        Integer criticalSlaDays,
        Integer highSlaDays,
        Integer mediumSlaDays,
        Integer lowSlaDays,
        Double assetCriticalSlaMultiplier,
        Double assetHighSlaMultiplier,
        Double assetMediumSlaMultiplier,
        Double assetLowSlaMultiplier,
        Boolean autoCloseEnabled,
        String autoCloseAssetIdentifier,
        Integer autoCloseAfterDays,
        String findingGenerationMode,
        String findingsScoreConfig,
        Double agentAutoThreshold,
        Double agentReviewThreshold,
        Integer agentMaxConcurrent
) {
}
