package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class PrecedenceResolverServiceTest {

    private final PrecedenceResolverService service = new PrecedenceResolverService();

    @Test
    void returnsUnknownWhenNoCandidates() {
        PrecedenceResolverService.PrecedenceResolution resolution = service.resolve(List.of());

        assertEquals(PrecedenceResolverService.FinalState.UNKNOWN, resolution.finalState());
        assertEquals("no_candidates", resolution.reason());
        assertTrue(resolution.sourcePrecedence().isEmpty());
        assertTrue(resolution.considered().isEmpty());
    }

    @Test
    void vexNotAffectedOverridesAdvisoryAffected() {
        PrecedenceResolverService.CandidateDecision vexFalse = candidate(
                "microsoft-vex",
                "repo-exact+version",
                0,
                0.91,
                ApplicabilityDecisionService.ApplicabilityResult.FALSE,
                "vex_not_affected"
        );
        PrecedenceResolverService.CandidateDecision advisoryTrue = candidate(
                "advisory",
                "advisory-package-exact+version",
                1,
                0.88,
                ApplicabilityDecisionService.ApplicabilityResult.TRUE,
                "within_constraints"
        );

        PrecedenceResolverService.PrecedenceResolution resolution = service.resolve(List.of(advisoryTrue, vexFalse));

        assertEquals(PrecedenceResolverService.FinalState.NOT_AFFECTED, resolution.finalState());
        assertEquals("authoritative_source_not_affected_override", resolution.reason());
        assertEquals(vexFalse, resolution.primary());
        assertNotNull(resolution.precedenceTrace());
        assertEquals("source-precedence-v2", resolution.precedenceTrace().get("engine"));
    }

    @Test
    void staleVexNotAffectedDoesNotOverrideAdvisoryAffected() {
        PrecedenceResolverService.CandidateDecision staleVexFalse = candidate(
                "microsoft-vex",
                "repo-exact+version",
                0,
                0.83,
                ApplicabilityDecisionService.ApplicabilityResult.FALSE,
                "vex_not_affected_stale_or_untrusted"
        );
        PrecedenceResolverService.CandidateDecision advisoryTrue = candidate(
                "advisory",
                "advisory-package-exact+version",
                1,
                0.88,
                ApplicabilityDecisionService.ApplicabilityResult.TRUE,
                "within_constraints"
        );

        PrecedenceResolverService.PrecedenceResolution resolution = service.resolve(List.of(advisoryTrue, staleVexFalse));

        assertEquals(PrecedenceResolverService.FinalState.AFFECTED, resolution.finalState());
        assertEquals("highest_precedence_affected", resolution.reason());
        assertEquals(advisoryTrue, resolution.primary());
    }

    @Test
    void kevAffectedAloneReturnsUnknownNotAffected() {
        // BLG-004: KEV says a CVE is being actively exploited somewhere in the world,
        // but does not provide product/version applicability. A KEV-only candidate must
        // NOT produce FinalState.AFFECTED — it should return UNKNOWN.
        PrecedenceResolverService.CandidateDecision kevTrue = candidate(
                "kev",
                "kev-annotation",
                3,
                0.5,
                ApplicabilityDecisionService.ApplicabilityResult.TRUE,
                "within_constraints"
        );

        PrecedenceResolverService.PrecedenceResolution resolution = service.resolve(List.of(kevTrue));

        assertEquals(PrecedenceResolverService.FinalState.UNKNOWN, resolution.finalState());
        // KEV candidate must still appear in the considered list for audit trail
        assertEquals(1, resolution.considered().size());
    }

    @Test
    void kevAffectedDoesNotOverrideNvdNotAffected() {
        // BLG-004: KEV must not override a real NOT_AFFECTED finding from NVD/advisory.
        PrecedenceResolverService.CandidateDecision kevTrue = candidate(
                "kev",
                "kev-annotation",
                3,
                0.5,
                ApplicabilityDecisionService.ApplicabilityResult.TRUE,
                "within_constraints"
        );
        PrecedenceResolverService.CandidateDecision nvdFalse = candidate(
                "nvd",
                "cpe-direct+version",
                2,
                0.85,
                ApplicabilityDecisionService.ApplicabilityResult.FALSE,
                "exact_version_mismatch"
        );

        PrecedenceResolverService.PrecedenceResolution resolution = service.resolve(List.of(kevTrue, nvdFalse));

        assertEquals(PrecedenceResolverService.FinalState.NOT_AFFECTED, resolution.finalState());
        assertEquals(nvdFalse, resolution.primary());
    }

    @Test
    void advisoryAffectedWinsOverNvdAffected() {
        PrecedenceResolverService.CandidateDecision nvdTrue = candidate(
                "nvd",
                "cpe-direct+version",
                2,
                0.72,
                ApplicabilityDecisionService.ApplicabilityResult.TRUE,
                "nvd_config_match"
        );
        PrecedenceResolverService.CandidateDecision advisoryTrue = candidate(
                "advisory",
                "advisory-package-exact+version",
                1,
                0.86,
                ApplicabilityDecisionService.ApplicabilityResult.TRUE,
                "within_constraints"
        );

        PrecedenceResolverService.PrecedenceResolution resolution = service.resolve(List.of(nvdTrue, advisoryTrue));

        assertEquals(PrecedenceResolverService.FinalState.AFFECTED, resolution.finalState());
        assertEquals("highest_precedence_affected", resolution.reason());
        assertEquals(advisoryTrue, resolution.primary());
    }

    @Test
    void returnsUnknownWhenOnlyUnknownCandidatesRemain() {
        PrecedenceResolverService.CandidateDecision unknown = candidate(
                "nvd",
                "cpe-fallback+version",
                5,
                0.41,
                ApplicabilityDecisionService.ApplicabilityResult.UNKNOWN,
                "nvd_config_unknown"
        );

        PrecedenceResolverService.PrecedenceResolution resolution = service.resolve(List.of(unknown));

        assertEquals(PrecedenceResolverService.FinalState.UNKNOWN, resolution.finalState());
        assertEquals("no_decisive_candidate", resolution.reason());
        assertEquals(unknown, resolution.primary());
        assertTrue(resolution.considered().size() == 1);
    }

    private PrecedenceResolverService.CandidateDecision candidate(
            String source,
            String matchedBy,
            int rank,
            double confidence,
            ApplicabilityDecisionService.ApplicabilityResult result,
            String reason
    ) {
        VulnerabilityTarget target = new VulnerabilityTarget();
        target.setSource(source);
        target.setNormalizedTargetKey(source + "::target");

        ApplicabilityDecisionService.ApplicabilityDecision decision =
                new ApplicabilityDecisionService.ApplicabilityDecision(result, reason, Map.of("reason", reason));

        return new PrecedenceResolverService.CandidateDecision(
                target,
                matchedBy,
                rank,
                confidence,
                Map.of("base", confidence),
                decision
        );
    }
}
