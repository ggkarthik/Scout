package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.aisecurity.policy.AiGridPredicateEngine;
import com.prototype.vulnwatch.aisecurity.policy.AiSecurityResourceFamilyCatalogue;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

class AiGridAssessmentServiceTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final AiGridAssessmentService service = new AiGridAssessmentService(
            mock(NamedParameterJdbcTemplate.class), mapper, new AiGridPredicateEngine(),
            new AiSecurityResourceFamilyCatalogue(), mock(AiGridFindingService.class),
            mock(AiGridSnapshotService.class), mock(AiGridCapabilityService.class),
            mock(AiGridGraphEvidenceResolver.class));

    @Test
    void declaredMinimumConfidenceRejectsMissingAndInsufficientConfidence() throws Exception {
        var requirement = service.requirements("""
                [{"factKey":"derived.reachability","valueType":"BOOLEAN",
                  "evidenceClasses":["GRAPH_ANALYSIS"],"maxAgeSeconds":3600,"minConfidence":0.9}]
                """).get(0);
        Instant asOf = Instant.parse("2026-08-02T12:00:00Z");

        assertEquals(0.9, requirement.minConfidence());
        assertEquals("LOW_CONFIDENCE", service.issue(new AiGridAssessmentService.Fact(
                UUID.randomUUID(), "BOOLEAN", mapper.readTree("true"), "KNOWN", "GRAPH_ANALYSIS",
                asOf.minusSeconds(60), null), requirement, asOf));
        assertEquals("LOW_CONFIDENCE", service.issue(new AiGridAssessmentService.Fact(
                UUID.randomUUID(), "BOOLEAN", mapper.readTree("true"), "KNOWN", "GRAPH_ANALYSIS",
                asOf.minusSeconds(60), 0.89), requirement, asOf));
        assertEquals(null, service.issue(new AiGridAssessmentService.Fact(
                UUID.randomUUID(), "BOOLEAN", mapper.readTree("true"), "KNOWN", "GRAPH_ANALYSIS",
                asOf.minusSeconds(60), 0.9), requirement, asOf));
    }

    @Test
    void postureFindingFingerprintIsStableAndPolicyScopedSoReplacementsReconcile() {
        UUID tenant = UUID.fromString("00000000-0000-0000-0000-000000000001");
        UUID subject = UUID.fromString("00000000-0000-0000-0000-0000000000ab");

        // Locked format: sha256(tenant|AI_POSTURE|policyId|ARTIFACT|subjectId), lowercase hex.
        // The Phase 1 migration re-keys legacy findings with this exact helper, so it must never
        // drift from what the assessment engine computes — otherwise replacements duplicate findings.
        String fingerprint = AiGridAssessmentService.postureFindingFingerprint(tenant, "AGCF-AWS-002", subject);
        assertEquals("4dbc1aed681b3df495c4652e0a16c347296cbbba346c5dcf616fed4829dd246c", fingerprint);
        assertEquals(64, fingerprint.length());

        // Legacy and successor policy ids produce different identities (why re-keying is required),
        // and the successor identity is deterministic (why re-keying reconciles instead of duplicating).
        String legacy = AiGridAssessmentService.postureFindingFingerprint(tenant, "AWS_BEDROCK_WEAK_GUARDRAIL", subject);
        String successor = AiGridAssessmentService.postureFindingFingerprint(tenant, "AGCF-AWS-002", subject);
        org.junit.jupiter.api.Assertions.assertNotEquals(legacy, successor);
        assertEquals(successor, AiGridAssessmentService.postureFindingFingerprint(tenant, "AGCF-AWS-002", subject));
    }

    @Test
    void directRelationshipNeedsAReadyTargetBeforeItCanPassAndFailsWhenAnyTargetMatches() {
        var unavailable = AiGridAssessmentService.decideDirectTargets(List.of(false), List.of("relationship:one:fact:guardrail:MISSING"));
        var pass = AiGridAssessmentService.decideDirectTargets(List.of(false, false), List.of());
        var fail = AiGridAssessmentService.decideDirectTargets(List.of(false, true), List.of("relationship:other:fact:guardrail:MISSING"));

        assertEquals("NO_DECISION", unavailable.decision());
        assertEquals("PASS", pass.decision());
        assertEquals("FAIL", fail.decision());
    }
}
