package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.domain.Vulnerability;
import java.util.Map;
import org.springframework.stereotype.Service;

@Service
public class RiskScoringService {

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
        // Risk scoring via RiskScoringService is no longer used for persisted finding risk_score.
        // Finding risk_score is now derived exclusively from FindingsScoreService.computeFromParts().
        // This method is retained only because RiskScoreOutcome is referenced by FindingEvidenceService.
        return new RiskScoreOutcome(0.0, Map.of(), Map.of());
    }

    public record RiskScoreOutcome(
            double score,
            Map<String, Double> breakdown,
            Map<String, Object> vexContext
    ) {
    }
}
