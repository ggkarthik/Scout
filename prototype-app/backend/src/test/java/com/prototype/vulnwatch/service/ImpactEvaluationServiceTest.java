package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.ImpactState;
import com.prototype.vulnwatch.domain.VersionScheme;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ImpactEvaluationServiceTest {

    private final ImpactEvaluationService service = new ImpactEvaluationService();

    @Test
    void applicableWithoutVexProducesImpactedFinding() {
        PrecedenceResolverService.CandidateDecision selected = candidate(
                ApplicabilityDecisionService.ApplicabilityResult.TRUE,
                "within_constraints"
        );
        PrecedenceResolverService.PrecedenceResolution resolution = new PrecedenceResolverService.PrecedenceResolution(
                PrecedenceResolverService.FinalState.AFFECTED,
                selected,
                "highest_precedence_affected",
                List.of(),
                List.of(),
                Map.of()
        );

        ImpactEvaluationService.ImpactAssessment assessment =
                service.evaluate(resolution, selected, ImpactEvaluationService.VexOverlayOutcome.none());

        assertEquals(ImpactState.IMPACTED, assessment.impactState());
        assertEquals("applicable_no_vex", assessment.impactReason());
        assertTrue(assessment.findingEligible());
        assertEquals(FindingDecisionState.AFFECTED, assessment.findingDecisionState());
    }

    @Test
    void exactVexAffectedProducesImpactedFindingEligibleState() {
        PrecedenceResolverService.CandidateDecision selected = candidate(
                ApplicabilityDecisionService.ApplicabilityResult.TRUE,
                "within_constraints"
        );
        PrecedenceResolverService.PrecedenceResolution resolution = new PrecedenceResolverService.PrecedenceResolution(
                PrecedenceResolverService.FinalState.AFFECTED,
                selected,
                "highest_precedence_affected",
                List.of(),
                List.of(),
                Map.of()
        );

        ImpactEvaluationService.ImpactAssessment assessment = service.evaluate(
                resolution,
                selected,
                new ImpactEvaluationService.VexOverlayOutcome(
                        true,
                        PrecedenceResolverService.FinalState.AFFECTED,
                        "AFFECTED",
                        "microsoft",
                        "FRESH",
                        "vex-microsoft",
                        null,
                        selected.target().getId(),
                        null,
                        "highest_precedence_affected"
                )
        );

        assertEquals(ImpactState.IMPACTED, assessment.impactState());
        assertEquals("vex_affected", assessment.impactReason());
        assertTrue(assessment.findingEligible());
        assertEquals(FindingDecisionState.AFFECTED, assessment.findingDecisionState());
    }

    private PrecedenceResolverService.CandidateDecision candidate(
            ApplicabilityDecisionService.ApplicabilityResult result,
            String reason
    ) {
        VulnerabilityTarget target = new VulnerabilityTarget();
        target.setVersionScheme(VersionScheme.SEMVER);
        target.setVersionStart("1.0.0");
        target.setStartInclusive(true);
        target.setVersionEnd("2.0.0");
        target.setEndInclusive(false);
        target.setSource("ghsa");
        return new PrecedenceResolverService.CandidateDecision(
                target,
                "vendor_product_version",
                1,
                0.91,
                Map.of("base", 0.91),
                new ApplicabilityDecisionService.ApplicabilityDecision(result, reason, Map.of("componentVersion", "1.2.3"))
        );
    }
}
