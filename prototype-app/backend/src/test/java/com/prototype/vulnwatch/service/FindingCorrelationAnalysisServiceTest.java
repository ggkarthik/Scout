package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import com.prototype.vulnwatch.repo.VulnerabilityConfigExprRepository;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class FindingCorrelationAnalysisServiceTest {

    @Mock private VulnerabilityConfigExprRepository vulnerabilityConfigExprRepository;
    @Mock private ApplicabilityDecisionService applicabilityDecisionService;
    @Mock private NvdConfigurationDecisionService nvdConfigurationDecisionService;
    @Mock private PrecedenceResolverService precedenceResolverService;

    private FindingCorrelationAnalysisService service;

    @BeforeEach
    void setUp() {
        service = new FindingCorrelationAnalysisService(
                vulnerabilityConfigExprRepository,
                applicabilityDecisionService,
                nvdConfigurationDecisionService,
                precedenceResolverService
        );
        // Default: non-CPE confidence threshold = 0.68
        ReflectionTestUtils.setField(service, "nonCpeCreateMinConfidence", 0.68);
    }

    // ── buildCandidateDecisionsByVulnerability ──────────────────────────────

    @Test
    void buildCandidateDecisions_mapsCandidateToDecisionByVulnerabilityId() {
        Vulnerability vuln = vuln("CVE-2024-0001");
        VulnerabilityTarget target = nvdTarget(vuln);
        CorrelationCandidateService.CandidateMatch candidate = match(target, "cpe-nvd", 1, 0.95);
        InventoryComponent component = component("openssl", "3.0.2");

        when(vulnerabilityConfigExprRepository.findByVulnerabilityInAndSource(any(), any()))
                .thenReturn(List.of());
        when(applicabilityDecisionService.evaluateCorrelation(any(), any(), any()))
                .thenReturn(trueDecision("within_constraints"));
        when(nvdConfigurationDecisionService.evaluate(any(), anyList()))
                .thenReturn(unknownDecision("no_tree"));

        Map<UUID, List<PrecedenceResolverService.CandidateDecision>> result =
                service.buildCandidateDecisionsByVulnerability(component, List.of(candidate), new RiskPolicy());

        assertNotNull(result);
        assertEquals(1, result.size());
        List<PrecedenceResolverService.CandidateDecision> decisions = result.get(vuln.getId());
        assertNotNull(decisions);
        assertEquals(1, decisions.size());
        assertEquals("cpe-nvd", decisions.get(0).matchedBy());
    }

    @Test
    void buildCandidateDecisions_appliesApplicabilityPenaltyForCompareError() {
        Vulnerability vuln = vuln("CVE-2024-0002");
        VulnerabilityTarget target = nvdTarget(vuln);
        CorrelationCandidateService.CandidateMatch candidate = match(target, "cpe-nvd", 1, 0.90);
        InventoryComponent component = component("curl", "7.80.0");

        when(vulnerabilityConfigExprRepository.findByVulnerabilityInAndSource(any(), any()))
                .thenReturn(List.of());
        when(applicabilityDecisionService.evaluateCorrelation(any(), any(), any()))
                .thenReturn(unknownDecision("compare_error"));
        when(nvdConfigurationDecisionService.evaluate(any(), anyList()))
                .thenReturn(unknownDecision("no_tree"));

        Map<UUID, List<PrecedenceResolverService.CandidateDecision>> result =
                service.buildCandidateDecisionsByVulnerability(component, List.of(candidate), new RiskPolicy());

        PrecedenceResolverService.CandidateDecision decision = result.get(vuln.getId()).get(0);
        // Penalty of 0.12 applied: 0.90 - 0.12 = 0.78
        assertEquals(0.78, decision.confidence(), 0.001);
        assertEquals(0.12, decision.confidenceBreakdown().get("applicabilityPenalty"), 0.001);
    }

    @Test
    void buildCandidateDecisions_nvdTreeFalseOverridesTargetDecision() {
        Vulnerability vuln = vuln("CVE-2024-0003");
        VulnerabilityTarget target = nvdTarget(vuln);
        CorrelationCandidateService.CandidateMatch candidate = match(target, "cpe-nvd", 1, 0.95);
        InventoryComponent component = component("nginx", "1.22.0");

        when(vulnerabilityConfigExprRepository.findByVulnerabilityInAndSource(any(), any()))
                .thenReturn(List.of());
        when(applicabilityDecisionService.evaluateCorrelation(any(), any(), any()))
                .thenReturn(trueDecision("within_constraints"));
        when(nvdConfigurationDecisionService.evaluate(any(), anyList()))
                .thenReturn(falseDecision("no_match_in_tree"));

        Map<UUID, List<PrecedenceResolverService.CandidateDecision>> result =
                service.buildCandidateDecisionsByVulnerability(component, List.of(candidate), new RiskPolicy());

        PrecedenceResolverService.CandidateDecision decision = result.get(vuln.getId()).get(0);
        assertEquals(ApplicabilityDecisionService.ApplicabilityResult.FALSE,
                decision.applicabilityDecision().result());
        assertEquals("nvd_config_override_not_affected", decision.applicabilityDecision().reason());
    }

    @Test
    void buildCandidateDecisions_returnsEmptyMapForEmptyCandidates() {
        Map<UUID, List<PrecedenceResolverService.CandidateDecision>> result =
                service.buildCandidateDecisionsByVulnerability(component("openssl", "3.0.0"), List.of(), new RiskPolicy());
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    // ── selectAutomaticFindingCandidate ─────────────────────────────────────

    @Test
    void selectCandidate_returnsNullWhenResolutionIsNull() {
        assertNull(service.selectAutomaticFindingCandidate(null, List.of()));
    }

    @Test
    void selectCandidate_returnsNullWhenPrimaryIsNotAffected() {
        PrecedenceResolverService.CandidateDecision primary = decision("cpe-nvd", 0.95, false);
        PrecedenceResolverService.PrecedenceResolution resolution = resolution(
                PrecedenceResolverService.FinalState.NOT_AFFECTED, primary);

        assertNull(service.selectAutomaticFindingCandidate(resolution, List.of(primary)));
    }

    @Test
    void selectCandidate_returnsPrimaryWhenCpeMatchedAndAffected() {
        PrecedenceResolverService.CandidateDecision primary = decision("cpe-nvd", 0.95, true);
        PrecedenceResolverService.PrecedenceResolution resolution = resolution(
                PrecedenceResolverService.FinalState.AFFECTED, primary);

        PrecedenceResolverService.CandidateDecision result =
                service.selectAutomaticFindingCandidate(resolution, List.of(primary));

        assertNotNull(result);
        assertEquals("cpe-nvd", result.matchedBy());
    }

    @Test
    void selectCandidate_returnsNullWhenNonCpeConfidenceBelowThreshold() {
        PrecedenceResolverService.CandidateDecision primary = decision("identity-purl", 0.50, true);
        PrecedenceResolverService.PrecedenceResolution resolution = resolution(
                PrecedenceResolverService.FinalState.AFFECTED, primary);
        when(precedenceResolverService.sourcePriority(any())).thenReturn(1);

        PrecedenceResolverService.CandidateDecision result =
                service.selectAutomaticFindingCandidate(resolution, List.of(primary));

        assertNull(result, "Non-CPE match below 0.68 threshold should not create a finding");
    }

    @Test
    void selectCandidate_returnsNonCpeWhenConfidenceAtOrAboveThreshold() {
        PrecedenceResolverService.CandidateDecision primary = decision("identity-purl", 0.75, true);
        PrecedenceResolverService.PrecedenceResolution resolution = resolution(
                PrecedenceResolverService.FinalState.AFFECTED, primary);

        PrecedenceResolverService.CandidateDecision result =
                service.selectAutomaticFindingCandidate(resolution, List.of(primary));

        assertNotNull(result);
        assertEquals("identity-purl", result.matchedBy());
    }

    // ── categorizeNotApplicableReason ───────────────────────────────────────

    @Test
    void categorize_staleOrUntrustedVex() {
        assertEquals("VEX Stale Or Untrusted",
                service.categorizeNotApplicableReason("stale_or_untrusted", null, null));
    }

    @Test
    void categorize_vexNotAffected() {
        assertEquals("VEX Not Affected",
                service.categorizeNotApplicableReason("vex_not_affected", null, null));
    }

    @Test
    void categorize_vexFixed() {
        assertEquals("VEX Fixed",
                service.categorizeNotApplicableReason("vex_fixed", null, null));
    }

    @Test
    void categorize_nvdConfigurationNotAffected() {
        assertEquals("NVD Configuration Not Affected",
                service.categorizeNotApplicableReason("nvd_config_override_not_affected", null, null));
    }

    @Test
    void categorize_versionOutsideAffectedRange() {
        assertEquals("Version Outside Affected Range",
                service.categorizeNotApplicableReason("exact_version_mismatch", null, null));
        assertEquals("Version Outside Affected Range",
                service.categorizeNotApplicableReason("below_introduced", null, null));
        assertEquals("Version Outside Affected Range",
                service.categorizeNotApplicableReason("at_or_above_fixed", null, null));
    }

    @Test
    void categorize_vendorAdvisoryNotAffected() {
        assertEquals("Vendor Advisory Not Affected",
                service.categorizeNotApplicableReason(
                        "other_reason",
                        "highest_precedence_not_affected",
                        "csaf-microsoft"
                ));
    }

    @Test
    void categorize_fallsBackToCorrelationNotAffected() {
        assertEquals("Correlation Not Affected",
                service.categorizeNotApplicableReason("some_other_reason", "other_precedence", "nvd"));
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    private Vulnerability vuln(String cveId) {
        Vulnerability v = new Vulnerability();
        ReflectionTestUtils.setField(v, "id", UUID.randomUUID());
        v.setExternalId(cveId);
        return v;
    }

    private VulnerabilityTarget nvdTarget(Vulnerability vuln) {
        VulnerabilityTarget t = new VulnerabilityTarget();
        t.setVulnerability(vuln);
        t.setSource("nvd");
        t.setVersionStart("1.0.0");
        t.setStartInclusive(true);
        t.setVersionEnd("3.0.0");
        t.setEndInclusive(false);
        return t;
    }

    private InventoryComponent component(String name, String version) {
        InventoryComponent c = new InventoryComponent();
        ReflectionTestUtils.setField(c, "id", UUID.randomUUID());
        c.setPackageName(name);
        c.setVersion(version);
        return c;
    }

    private CorrelationCandidateService.CandidateMatch match(
            VulnerabilityTarget target, String matchedBy, int rank, double confidence
    ) {
        return new CorrelationCandidateService.CandidateMatch(
                target, matchedBy, rank, confidence, new HashMap<>(Map.of("base", confidence))
        );
    }

    private ApplicabilityDecisionService.ApplicabilityDecision trueDecision(String reason) {
        return new ApplicabilityDecisionService.ApplicabilityDecision(
                ApplicabilityDecisionService.ApplicabilityResult.TRUE, reason, Map.of());
    }

    private ApplicabilityDecisionService.ApplicabilityDecision falseDecision(String reason) {
        return new ApplicabilityDecisionService.ApplicabilityDecision(
                ApplicabilityDecisionService.ApplicabilityResult.FALSE, reason, Map.of());
    }

    private ApplicabilityDecisionService.ApplicabilityDecision unknownDecision(String reason) {
        return new ApplicabilityDecisionService.ApplicabilityDecision(
                ApplicabilityDecisionService.ApplicabilityResult.UNKNOWN, reason, Map.of());
    }

    private PrecedenceResolverService.CandidateDecision decision(String matchedBy, double confidence, boolean affected) {
        VulnerabilityTarget target = new VulnerabilityTarget();
        target.setSource("ghsa");
        ReflectionTestUtils.setField(target, "id", UUID.randomUUID());
        return new PrecedenceResolverService.CandidateDecision(
                target, matchedBy, 1, confidence, new HashMap<>(Map.of("base", confidence)),
                affected ? trueDecision("within_constraints") : falseDecision("version_mismatch")
        );
    }

    private PrecedenceResolverService.PrecedenceResolution resolution(
            PrecedenceResolverService.FinalState state,
            PrecedenceResolverService.CandidateDecision primary
    ) {
        return new PrecedenceResolverService.PrecedenceResolution(
                state, primary, "test_reason", List.of(), List.of(), Map.of()
        );
    }

    private boolean assertTrue(boolean condition) {
        org.junit.jupiter.api.Assertions.assertTrue(condition);
        return condition;
    }

    private boolean assertTrue(Map<?, ?> map) {
        return !map.isEmpty();
    }
}
