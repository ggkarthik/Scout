package com.prototype.vulnwatch.dto;

public record RiskPolicyRequest(
        Double cvssWeight,
        Double kevBoost,
        Double epssWeight,
        Integer vexNotAffectedFreshnessDays,
        Integer vexFixedFreshnessDays,
        Double vexKnownAffectedBoost,
        Double vexUnderInvestigationPenalty,
        Double vexNotAffectedReduction,
        Double vexStalePenalty,
        Double criticalThreshold,
        Double highThreshold,
        Double assetCriticalRiskBoost,
        Double assetHighRiskBoost,
        Double assetMediumRiskBoost,
        Double assetLowRiskBoost,
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
        String findingGenerationMode
) {
}
