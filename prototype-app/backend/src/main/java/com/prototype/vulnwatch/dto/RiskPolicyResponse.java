package com.prototype.vulnwatch.dto;

public record RiskPolicyResponse(
        double cvssWeight,
        double kevBoost,
        double epssWeight,
        int vexNotAffectedFreshnessDays,
        int vexFixedFreshnessDays,
        double vexKnownAffectedBoost,
        double vexUnderInvestigationPenalty,
        double vexNotAffectedReduction,
        double vexStalePenalty,
        double criticalThreshold,
        double highThreshold,
        double assetCriticalRiskBoost,
        double assetHighRiskBoost,
        double assetMediumRiskBoost,
        double assetLowRiskBoost,
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
        String findingGenerationMode
) {
}
