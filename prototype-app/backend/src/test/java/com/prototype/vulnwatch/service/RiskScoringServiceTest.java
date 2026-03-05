package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.BusinessCriticality;
import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class RiskScoringServiceTest {

    private final RiskScoringService service = new RiskScoringService();

    @Test
    void appliesVexKnownAffectedBoost() {
        Vulnerability vulnerability = vulnerability(8.0, 0.2, false);
        RiskPolicy policy = policy();
        policy.setVexKnownAffectedBoost(0.8);

        PrecedenceResolverService.CandidateDecision selected = candidate("vex_known_affected");

        RiskScoringService.RiskScoreOutcome outcome = service.score(vulnerability, policy, asset(), selected, null);

        assertEquals(0.8, outcome.breakdown().get("vexKnownAffectedBoost"));
        assertTrue(outcome.score() > 8.0);
    }

    @Test
    void appliesStalePenaltyWhenStaleVexSignalExists() {
        Vulnerability vulnerability = vulnerability(6.5, 0.1, false);
        RiskPolicy policy = policy();
        policy.setVexStalePenalty(0.6);

        PrecedenceResolverService.PrecedenceResolution resolution = new PrecedenceResolverService.PrecedenceResolution(
                PrecedenceResolverService.FinalState.AFFECTED,
                candidate("within_constraints"),
                "highest_precedence_affected",
                List.of(),
                List.of(Map.of("applicabilityReason", "vex_not_affected_stale_or_untrusted")),
                Map.of()
        );

        RiskScoringService.RiskScoreOutcome outcome = service.score(
                vulnerability,
                policy,
                asset(),
                candidate("within_constraints"),
                resolution
        );

        assertEquals(0.6, outcome.breakdown().get("vexStalePenalty"));
        assertEquals(1, outcome.vexContext().get("staleSignalCount"));
    }

    private Vulnerability vulnerability(double cvss, double epss, boolean kev) {
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setExternalId("CVE-2099-0001");
        vulnerability.setSeverity("HIGH");
        vulnerability.setCvssScore(cvss);
        vulnerability.setEpssScore(epss);
        vulnerability.setInKev(kev);
        return vulnerability;
    }

    private RiskPolicy policy() {
        RiskPolicy policy = new RiskPolicy();
        policy.setCvssWeight(1.0);
        policy.setEpssWeight(1.0);
        policy.setKevBoost(2.0);
        policy.setVexKnownAffectedBoost(0.4);
        policy.setVexUnderInvestigationPenalty(0.2);
        policy.setVexNotAffectedReduction(0.8);
        policy.setVexStalePenalty(0.5);
        return policy;
    }

    private Asset asset() {
        Asset asset = new Asset();
        asset.setBusinessCriticality(BusinessCriticality.LOW);
        return asset;
    }

    private PrecedenceResolverService.CandidateDecision candidate(String applicabilityReason) {
        VulnerabilityTarget target = new VulnerabilityTarget();
        target.setSource("vex-microsoft");
        return new PrecedenceResolverService.CandidateDecision(
                target,
                "repo-exact+version",
                0,
                0.9,
                Map.of(),
                new ApplicabilityDecisionService.ApplicabilityDecision(
                        ApplicabilityDecisionService.ApplicabilityResult.TRUE,
                        applicabilityReason,
                        Map.of("reason", applicabilityReason)
                )
        );
    }
}
