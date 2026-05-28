package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.ApplicabilityState;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.ComponentVulnerabilityState;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingCreationSource;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.ImpactState;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import java.time.Instant;
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
class FindingCorrelationMutationServiceTest {

    @Mock private CorrelationCandidateService correlationCandidateService;
    @Mock private ImpactEvaluationService impactEvaluationService;
    @Mock private VexAssertionMatchService vexAssertionMatchService;
    @Mock private FindingSlaService findingSlaService;
    @Mock private OwnershipRuleService ownershipRuleService;

    private FindingCorrelationMutationService service;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        service = new FindingCorrelationMutationService(
                correlationCandidateService,
                impactEvaluationService,
                vexAssertionMatchService,
                findingSlaService,
                ownershipRuleService,
                objectMapper
        );
    }

    // ── upsertComponentVulnerabilityState ───────────────────────────────────

    @Test
    void upsert_skipsWhenTenantIsNull() {
        List<ComponentVulnerabilityState> toPersist = new ArrayList<>();
        service.upsertComponentVulnerabilityState(
                null, component(), vulnerability(), null, null, null,
                impact(ApplicabilityState.APPLICABLE, ImpactState.IMPACTED),
                Instant.now(), new HashMap<>(), toPersist
        );
        assertTrue(toPersist.isEmpty());
    }

    @Test
    void upsert_skipsWhenComponentIsNull() {
        List<ComponentVulnerabilityState> toPersist = new ArrayList<>();
        service.upsertComponentVulnerabilityState(
                tenant(), null, vulnerability(), null, null, null,
                impact(ApplicabilityState.APPLICABLE, ImpactState.IMPACTED),
                Instant.now(), new HashMap<>(), toPersist
        );
        assertTrue(toPersist.isEmpty());
    }

    @Test
    void upsert_skipsWhenVulnerabilityIsNull() {
        List<ComponentVulnerabilityState> toPersist = new ArrayList<>();
        service.upsertComponentVulnerabilityState(
                tenant(), component(), null, null, null, null,
                impact(ApplicabilityState.APPLICABLE, ImpactState.IMPACTED),
                Instant.now(), new HashMap<>(), toPersist
        );
        assertTrue(toPersist.isEmpty());
    }

    @Test
    void upsert_createsNewStateRowWhenNotInExistingMap() {
        Vulnerability vuln = vulnerability();
        List<ComponentVulnerabilityState> toPersist = new ArrayList<>();

        service.upsertComponentVulnerabilityState(
                tenant(), component(), vuln,
                candidateDecision("cpe-nvd", 0.95),
                resolution(),
                ImpactEvaluationService.VexOverlayOutcome.none(),
                impact(ApplicabilityState.APPLICABLE, ImpactState.IMPACTED),
                Instant.now(), new HashMap<>(), toPersist
        );

        assertEquals(1, toPersist.size());
        ComponentVulnerabilityState state = toPersist.get(0);
        assertEquals(ApplicabilityState.APPLICABLE, state.getApplicabilityState());
        assertEquals(ImpactState.IMPACTED, state.getImpactState());
        assertEquals("cpe-nvd", state.getMatchedBy());
        assertTrue(state.isEligibleForFinding());
    }

    @Test
    void upsert_noOpWhenAllFieldsUnchanged() {
        Vulnerability vuln = vulnerability();
        ComponentVulnerabilityState existing = new ComponentVulnerabilityState();
        existing.setApplicabilityState(ApplicabilityState.APPLICABLE);
        existing.setApplicabilityReason("within_constraints");
        existing.setApplicabilityReasonDetail(null);
        existing.setImpactState(ImpactState.IMPACTED);
        existing.setImpactReason("applicable_no_vex");
        existing.setImpactReasonDetail(null);
        existing.setVexStatus("UNKNOWN");
        existing.setVexProvider("unknown");
        existing.setVexFreshness("UNKNOWN");
        existing.setVexSource(null);
        existing.setMatchedVexAssertionId(null);
        existing.setPrecedenceReason("highest_precedence_affected");
        existing.setMatchedBy("cpe-nvd");
        existing.setSelectedTargetSource("unknown");
        existing.setConfidenceScore(0.95);

        Map<UUID, ComponentVulnerabilityState> existingMap = new HashMap<>();
        existingMap.put(vuln.getId(), existing);
        List<ComponentVulnerabilityState> toPersist = new ArrayList<>();

        service.upsertComponentVulnerabilityState(
                tenant(), component(), vuln,
                candidateDecision("cpe-nvd", 0.95),
                resolution(),
                ImpactEvaluationService.VexOverlayOutcome.none(),
                impact(ApplicabilityState.APPLICABLE, ImpactState.IMPACTED),
                Instant.now(), existingMap, toPersist
        );

        assertTrue(toPersist.isEmpty(), "Should not add to persist list when nothing changed");
    }

    @Test
    void upsert_mutatesRowWhenImpactStateChanges() {
        Vulnerability vuln = vulnerability();
        ComponentVulnerabilityState existing = new ComponentVulnerabilityState();
        existing.setApplicabilityState(ApplicabilityState.APPLICABLE);
        existing.setImpactState(ImpactState.IMPACTED);
        existing.setImpactReason("applicable_no_vex");
        existing.setVexStatus("UNKNOWN");
        existing.setVexProvider("unknown");
        existing.setVexFreshness("UNKNOWN");
        existing.setPrecedenceReason("highest_precedence_affected");
        existing.setMatchedBy("cpe-nvd");
        existing.setConfidenceScore(0.95);

        Map<UUID, ComponentVulnerabilityState> existingMap = new HashMap<>();
        existingMap.put(vuln.getId(), existing);
        List<ComponentVulnerabilityState> toPersist = new ArrayList<>();

        service.upsertComponentVulnerabilityState(
                tenant(), component(), vuln,
                candidateDecision("cpe-nvd", 0.95),
                resolution(),
                ImpactEvaluationService.VexOverlayOutcome.none(),
                impact(ApplicabilityState.NOT_APPLICABLE, ImpactState.NOT_IMPACTED),
                Instant.now(), existingMap, toPersist
        );

        assertEquals(1, toPersist.size());
        assertEquals(ApplicabilityState.NOT_APPLICABLE, toPersist.get(0).getApplicabilityState());
        assertEquals(ImpactState.NOT_IMPACTED, toPersist.get(0).getImpactState());
    }

    // ── createFinding ───────────────────────────────────────────────────────

    @Test
    void createFinding_populatesAllCoreFields() {
        Tenant tenant = tenant();
        Asset asset = new Asset();
        InventoryComponent comp = component();
        Vulnerability vuln = vulnerability();
        PrecedenceResolverService.CandidateDecision selected = candidateDecision("cpe-nvd", 0.92);
        PrecedenceResolverService.PrecedenceResolution res = resolution();
        Instant now = Instant.now();

        when(findingSlaService.deriveDueAt(any(), any(Double.class), any(), any())).thenReturn(null);

        Finding finding = service.createFinding(
                tenant, asset, comp, vuln, selected, res, 7.5, null, now, new RiskPolicy()
        );

        assertNotNull(finding);
        assertEquals(FindingStatus.OPEN, finding.getStatus());
        assertEquals(FindingDecisionState.AFFECTED, finding.getDecisionState());
        assertEquals(FindingCreationSource.AUTOMATIC, finding.getCreationSource());
        assertEquals("cpe-nvd", finding.getMatchedBy());
        assertEquals(7.5, finding.getRiskScore());
        assertEquals(0.92, finding.getConfidenceScore());
        assertNull(finding.getSuppressionReason());
        assertNull(finding.getSuppressedUntil());
        verify(ownershipRuleService).applyOwnerGroupToFinding(finding);
    }

    // ── setEvidenceWithVex ──────────────────────────────────────────────────

    @Test
    void setEvidenceWithVex_setsUnknownWhenEvidenceIsNull() {
        Finding finding = new Finding();
        service.setEvidenceWithVex(finding, null);

        assertEquals("UNKNOWN", finding.getVexStatus());
        assertEquals("UNKNOWN", finding.getVexFreshness());
        assertEquals("unknown", finding.getVexProvider());
        assertNull(finding.getMatchedVexAssertionId());
    }

    @Test
    void setEvidenceWithVex_extractsVexOverlayFromJson() throws Exception {
        when(impactEvaluationService.normalizeStatus("AFFECTED")).thenReturn("AFFECTED");
        when(impactEvaluationService.normalizeFreshness("FRESH")).thenReturn("FRESH");
        when(impactEvaluationService.normalizeProvider("microsoft")).thenReturn("microsoft");

        UUID assertionId = UUID.randomUUID();
        String evidence = objectMapper.writeValueAsString(Map.of(
                "vexOverlay", Map.of(
                        "status", "AFFECTED",
                        "freshness", "FRESH",
                        "provider", "microsoft",
                        "assertionId", assertionId.toString()
                )
        ));

        Finding finding = new Finding();
        service.setEvidenceWithVex(finding, evidence);

        assertEquals("AFFECTED", finding.getVexStatus());
        assertEquals("FRESH", finding.getVexFreshness());
        assertEquals("microsoft", finding.getVexProvider());
        assertEquals(assertionId, finding.getMatchedVexAssertionId());
    }

    @Test
    void setEvidenceWithVex_fallsBackToApplicabilityTraceWhenOverlayIsUnknown() throws Exception {
        when(impactEvaluationService.normalizeStatus("")).thenReturn("UNKNOWN");
        when(impactEvaluationService.normalizeFreshness("")).thenReturn("UNKNOWN");
        when(impactEvaluationService.normalizeProvider("")).thenReturn("unknown");
        when(impactEvaluationService.normalizeStatus("FIXED")).thenReturn("FIXED");
        when(impactEvaluationService.normalizeFreshness("FRESH")).thenReturn("FRESH");
        when(impactEvaluationService.normalizeProvider("redhat")).thenReturn("redhat");

        String evidence = objectMapper.writeValueAsString(Map.of(
                "applicabilityTrace", Map.of(
                        "vexStatus", "FIXED",
                        "vexFreshnessOutcome", "FRESH",
                        "vexProvider", "redhat"
                )
        ));

        Finding finding = new Finding();
        service.setEvidenceWithVex(finding, evidence);

        assertEquals("FIXED", finding.getVexStatus());
        assertEquals("FRESH", finding.getVexFreshness());
        assertEquals("redhat", finding.getVexProvider());
    }

    // ── withVexOverlayEvidence ──────────────────────────────────────────────

    @Test
    void withVexOverlayEvidence_returnsOriginalWhenOverlayNotApplied() {
        String original = "{\"key\":\"value\"}";
        ImpactEvaluationService.VexOverlayOutcome notApplied = ImpactEvaluationService.VexOverlayOutcome.none();

        String result = service.withVexOverlayEvidence(original, notApplied);

        assertEquals(original, result);
    }

    @Test
    void withVexOverlayEvidence_mergesOverlayIntoExistingEvidence() throws Exception {
        UUID assertionId = UUID.randomUUID();
        UUID targetId = UUID.randomUUID();
        ImpactEvaluationService.VexOverlayOutcome overlay = new ImpactEvaluationService.VexOverlayOutcome(
                true,
                PrecedenceResolverService.FinalState.NOT_AFFECTED,
                "NOT_AFFECTED",
                "microsoft",
                "FRESH",
                "vex-microsoft",
                assertionId,
                targetId,
                null,
                "vex_fixed"
        );
        String baseEvidence = objectMapper.writeValueAsString(Map.of("applicabilityTrace", Map.of("foo", "bar")));

        String result = service.withVexOverlayEvidence(baseEvidence, overlay);

        assertNotNull(result);
        Map<?, ?> parsed = objectMapper.readValue(result, Map.class);
        assertTrue(parsed.containsKey("vexOverlay"), "Result must contain vexOverlay key");
        assertTrue(parsed.containsKey("applicabilityTrace"), "Original keys must be preserved");
        Map<?, ?> vexOverlay = (Map<?, ?>) parsed.get("vexOverlay");
        assertEquals("NOT_AFFECTED", vexOverlay.get("state"));
        assertEquals("NOT_AFFECTED", vexOverlay.get("status"));
        assertEquals("microsoft", vexOverlay.get("provider"));
    }

    @Test
    void withVexOverlayEvidence_returnsJsonWhenBaseEvidenceIsNull() {
        ImpactEvaluationService.VexOverlayOutcome overlay = new ImpactEvaluationService.VexOverlayOutcome(
                true,
                PrecedenceResolverService.FinalState.AFFECTED,
                "AFFECTED",
                "nvd",
                "FRESH",
                "nvd",
                null,
                null,
                null,
                "applicable"
        );

        String result = service.withVexOverlayEvidence(null, overlay);

        assertNotNull(result);
        assertFalse(result.isBlank());
    }

    // ── resolveVexOverlay ───────────────────────────────────────────────────

    @Test
    void resolveVexOverlay_returnsNoneWhenComponentIsNull() {
        ImpactEvaluationService.VexOverlayOutcome result =
                service.resolveVexOverlay(null, UUID.randomUUID(), "nvd", null, null);
        assertFalse(result.applied());
    }

    @Test
    void resolveVexOverlay_returnsNoneWhenVulnerabilityIdIsNull() {
        ImpactEvaluationService.VexOverlayOutcome result =
                service.resolveVexOverlay(component(), null, "nvd", null, null);
        assertFalse(result.applied());
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    private Tenant tenant() {
        Tenant t = new Tenant();
        t.setId(UUID.fromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"));
        t.setSchemaName("tenant_test");
        return t;
    }

    private InventoryComponent component() {
        InventoryComponent c = new InventoryComponent();
        ReflectionTestUtils.setField(c, "id", UUID.fromString("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"));
        c.setPackageName("openssl");
        return c;
    }

    private Vulnerability vulnerability() {
        Vulnerability v = new Vulnerability();
        ReflectionTestUtils.setField(v, "id", UUID.fromString("cccccccc-cccc-cccc-cccc-cccccccccccc"));
        v.setExternalId("CVE-2024-0001");
        return v;
    }

    private PrecedenceResolverService.CandidateDecision candidateDecision(String matchedBy, double confidence) {
        VulnerabilityTarget target = new VulnerabilityTarget();
        return new PrecedenceResolverService.CandidateDecision(
                target, matchedBy, 1, confidence,
                new HashMap<>(Map.of("base", confidence)),
                new ApplicabilityDecisionService.ApplicabilityDecision(
                        ApplicabilityDecisionService.ApplicabilityResult.TRUE,
                        "within_constraints",
                        Map.of("componentVersion", "1.2.3")
                )
        );
    }

    private PrecedenceResolverService.PrecedenceResolution resolution() {
        return new PrecedenceResolverService.PrecedenceResolution(
                PrecedenceResolverService.FinalState.AFFECTED,
                candidateDecision("cpe-nvd", 0.95),
                "highest_precedence_affected",
                List.of(), List.of(), Map.of()
        );
    }

    private ImpactEvaluationService.ImpactAssessment impact(ApplicabilityState applicability, ImpactState impact) {
        return new ImpactEvaluationService.ImpactAssessment(
                applicability,
                applicability == ApplicabilityState.APPLICABLE ? "within_constraints" : "version_mismatch",
                null,
                impact,
                impact == ImpactState.IMPACTED ? "applicable_no_vex" : "not_impacted",
                null,
                impact == ImpactState.IMPACTED || impact == ImpactState.NO_PATCH,
                impact == ImpactState.IMPACTED ? FindingDecisionState.AFFECTED : FindingDecisionState.NOT_AFFECTED
        );
    }
}
