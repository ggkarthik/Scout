package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.BusinessCriticality;
import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.domain.Vulnerability;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class RiskScoringService {

    @Value("${app.features.vex-risk-modifiers-enabled:true}")
    private boolean vexRiskModifiersEnabled = true;

    public double score(Vulnerability vulnerability, RiskPolicy policy, Asset asset) {
        return score(vulnerability, policy, asset, null, null).score();
    }

    public RiskScoreOutcome score(
            Vulnerability vulnerability,
            RiskPolicy policy,
            Asset asset,
            PrecedenceResolverService.CandidateDecision selected,
            PrecedenceResolverService.PrecedenceResolution resolution
    ) {
        double cvss = vulnerability.getCvssScore() != null ? vulnerability.getCvssScore() : severityBaseline(vulnerability.getSeverity());
        double epss = vulnerability.getEpssScore() != null ? vulnerability.getEpssScore() * 10.0 : 0.0;

        double cvssContribution = cvss * policy.getCvssWeight();
        double epssContribution = epss * policy.getEpssWeight();
        double kevContribution = vulnerability.isInKev() ? policy.getKevBoost() : 0.0;
        double assetContribution = assetContextBoost(policy, asset);

        String selectedApplicabilityReason = selected == null || selected.applicabilityDecision() == null
                ? ""
                : safeLower(selected.applicabilityDecision().reason());
        int staleSignals = countStaleSignals(resolution);

        double vexKnownAffectedBoost = vexRiskModifiersEnabled && selectedApplicabilityReason.contains("vex_known_affected")
                ? policy.getVexKnownAffectedBoost()
                : 0.0;
        double vexUnderInvestigationPenalty = vexRiskModifiersEnabled && selectedApplicabilityReason.contains("vex_under_investigation")
                ? policy.getVexUnderInvestigationPenalty()
                : 0.0;
        double vexNotAffectedReduction = vexRiskModifiersEnabled && selectedApplicabilityReason.contains("vex_not_affected")
                ? policy.getVexNotAffectedReduction()
                : 0.0;
        double vexStalePenalty = vexRiskModifiersEnabled && staleSignals > 0 ? policy.getVexStalePenalty() : 0.0;

        double rawScore = cvssContribution
                + epssContribution
                + kevContribution
                + assetContribution
                + vexKnownAffectedBoost
                + vexStalePenalty
                - vexUnderInvestigationPenalty
                - vexNotAffectedReduction;
        double finalScore = Math.min(10.0, Math.max(0.0, rawScore));

        Map<String, Double> breakdown = new LinkedHashMap<>();
        breakdown.put("cvssContribution", cvssContribution);
        breakdown.put("epssContribution", epssContribution);
        breakdown.put("kevContribution", kevContribution);
        breakdown.put("assetContextBoost", assetContribution);
        breakdown.put("vexKnownAffectedBoost", vexKnownAffectedBoost);
        breakdown.put("vexStalePenalty", vexStalePenalty);
        breakdown.put("vexUnderInvestigationPenalty", vexUnderInvestigationPenalty);
        breakdown.put("vexNotAffectedReduction", vexNotAffectedReduction);
        breakdown.put("rawScore", rawScore);
        breakdown.put("finalScore", finalScore);

        Map<String, Object> vexContext = new LinkedHashMap<>();
        vexContext.put("selectedApplicabilityReason", selectedApplicabilityReason);
        vexContext.put("staleSignalCount", staleSignals);

        return new RiskScoreOutcome(finalScore, Map.copyOf(breakdown), Map.copyOf(vexContext));
    }

    private double assetContextBoost(RiskPolicy policy, Asset asset) {
        BusinessCriticality criticality = asset == null || asset.getBusinessCriticality() == null
                ? BusinessCriticality.MEDIUM
                : asset.getBusinessCriticality();
        return switch (criticality) {
            case CRITICAL -> policy.getAssetCriticalRiskBoost();
            case HIGH -> policy.getAssetHighRiskBoost();
            case MEDIUM -> policy.getAssetMediumRiskBoost();
            case LOW -> policy.getAssetLowRiskBoost();
        };
    }

    private double severityBaseline(String severity) {
        if (severity == null) {
            return 0.0;
        }
        return switch (severity.toUpperCase()) {
            case "CRITICAL" -> 9.8;
            case "HIGH" -> 8.0;
            case "MEDIUM" -> 5.5;
            case "LOW" -> 2.5;
            default -> 0.0;
        };
    }

    private int countStaleSignals(PrecedenceResolverService.PrecedenceResolution resolution) {
        if (resolution == null || resolution.considered() == null || resolution.considered().isEmpty()) {
            return 0;
        }
        int count = 0;
        for (Map<String, Object> candidate : resolution.considered()) {
            String reason = safeLower(candidate.get("applicabilityReason"));
            if (reason.contains("stale_or_untrusted")) {
                count++;
            }
        }
        return count;
    }

    private String safeLower(Object value) {
        if (!(value instanceof String text) || text.isBlank()) {
            return "";
        }
        return text.trim().toLowerCase(Locale.ROOT);
    }

    public record RiskScoreOutcome(
            double score,
            Map<String, Double> breakdown,
            Map<String, Object> vexContext
    ) {
    }
}
