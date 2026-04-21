package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;

public record CveInvestigationSummaryResponse(
        Instant generatedAt,
        String executiveSummary,
        RiskAnalysis riskAnalysis,
        ImpactAnalysis impactAnalysis,
        List<RemediationAction> remediationPlan,
        List<String> keyFindings,
        MetricsSummary metrics,
        String markdownReport
) {

    public record RiskAnalysis(
            String level,
            int score,
            String rationale
    ) {}

    public record ImpactAnalysis(
            int externalFacingCount,
            int internalAssetCount,
            String falsePositiveSummary,
            String eolRiskSummary,
            String patchGapSummary
    ) {}

    public record RemediationAction(
            int priority,
            String priorityLabel,
            String title,
            String detail,
            String owner,
            String timeframe,
            String type
    ) {}

    public record MetricsSummary(
            int totalAffected,
            int truePositives,
            int falsePositives,
            int externalFacing,
            int unpatchedVulnerable,
            int eolCount
    ) {}
}
