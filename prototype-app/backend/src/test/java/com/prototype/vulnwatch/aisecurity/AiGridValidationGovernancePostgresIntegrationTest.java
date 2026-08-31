package com.prototype.vulnwatch.aisecurity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.aisecurity.service.AiGridValidationGovernanceService;
import com.prototype.vulnwatch.aisecurity.service.AiGridValidationGovernanceService.CaseCommand;
import com.prototype.vulnwatch.aisecurity.service.AiGridValidationGovernanceService.EnvironmentCommand;
import com.prototype.vulnwatch.aisecurity.service.AiGridValidationGovernanceService.LabelCommand;
import com.prototype.vulnwatch.aisecurity.service.AiGridValidationGovernanceService.PrecisionReviewCommand;
import com.prototype.vulnwatch.aisecurity.service.AiGridValidationGovernanceService.PrecisionSampleCommand;
import com.prototype.vulnwatch.aisecurity.service.AiGridValidationGovernanceService.ResultCommand;
import com.prototype.vulnwatch.aisecurity.service.AiGridValidationGovernanceService.RunCommand;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.server.ResponseStatusException;

@PostgresIntegrationTest
class AiGridValidationGovernancePostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("ai_grid_validation_governance");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private AiGridValidationGovernanceService governance;
    @Autowired private NamedParameterJdbcTemplate jdbc;
    @Autowired private TenantService tenantService;
    @Autowired private TenantSchemaMigrationService tenantSchemaMigrationService;
    @Autowired private TenantSchemaExecutionService tenantExecution;

    @BeforeEach
    void seedCandidatePolicy() {
        TenantContext.runAsPlatform(() -> jdbc.update("""
                insert into platform.ai_grid_policy_versions (
                    policy_id, version, name, description, severity, lifecycle, workflow_class,
                    default_selection, artifact_types_json, required_capabilities_json,
                    required_relationships_json, required_resource_families_json, required_facts_json,
                    predicate_json, reason_code, remediation, framework_mappings_json,
                    native_kinds_json, scope_resolution)
                values ('GOVERNANCE_TEST_POLICY', '1.0.0', 'Governance test policy',
                    'Only publish after validation governance passes.', 'HIGH', 'VALIDATED',
                    'POSTURE_FINDING', 'PREVIEW', '["AI_AGENT"]', '[]', '[]', '["BEDROCK_AGENTS"]',
                    '[{"factKey":"bedrock.agent.guardrail_attached_configured","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":86400}]',
                    '{"fact":"bedrock.agent.guardrail_attached_configured","eq":false}',
                    'GOVERNANCE_TEST_REASON', 'Attach a guardrail.', '{"OWASP_LLM_TOP_10":["LLM01"]}',
                    '["AWS_BEDROCK_AGENT"]', 'STATIC')
                on conflict do nothing
                """, Map.of()));
        TenantContext.runAsPlatform(() -> jdbc.update("""
                insert into platform.ai_grid_policy_versions (
                    policy_id, version, name, description, severity, lifecycle, workflow_class,
                    default_selection, artifact_types_json, required_capabilities_json,
                    required_relationships_json, required_resource_families_json, required_facts_json,
                    predicate_json, reason_code, remediation, framework_mappings_json,
                    native_kinds_json, scope_resolution, release_family, package_digest)
                select 'GOVERNANCE_PHASE1_LOW_POLICY', version, 'Phase 1 low governance test policy',
                    description, 'LOW', lifecycle, workflow_class, default_selection,
                    artifact_types_json, required_capabilities_json, required_relationships_json,
                    required_resource_families_json, required_facts_json, predicate_json,
                    'GOVERNANCE_PHASE1_LOW_REASON', remediation, framework_mappings_json,
                    native_kinds_json, scope_resolution, 'AGCF_PHASE_1',
                    'phase-1-low-policy-material-digest'
                  from platform.ai_grid_policy_versions
                 where policy_id = 'GOVERNANCE_TEST_POLICY' and version = '1.0.0'
                on conflict do nothing
                """, Map.of()));
        TenantContext.runAsPlatform(() -> jdbc.update("""
                insert into platform.ai_grid_policy_versions (
                    policy_id, version, name, description, severity, lifecycle, workflow_class,
                    default_selection, artifact_types_json, required_capabilities_json,
                    required_relationships_json, required_resource_families_json, required_facts_json,
                    predicate_json, reason_code, remediation, framework_mappings_json,
                    native_kinds_json, scope_resolution)
                select 'GOVERNANCE_UNDERPOWERED_POLICY', version, 'Underpowered governance test policy',
                    description, severity, lifecycle, workflow_class, default_selection,
                    artifact_types_json, required_capabilities_json, required_relationships_json,
                    required_resource_families_json, required_facts_json, predicate_json,
                    'GOVERNANCE_UNDERPOWERED_REASON', remediation, framework_mappings_json,
                    native_kinds_json, scope_resolution
                  from platform.ai_grid_policy_versions
                 where policy_id = 'GOVERNANCE_TEST_POLICY' and version = '1.0.0'
                on conflict do nothing
                """, Map.of()));
    }

    @Test
    void blocksPublicationUntilFreshAnswerKeyAndDualReviewedPrecisionPass() {
        String policyId = "GOVERNANCE_TEST_POLICY";
        String version = "1.0.0";
        String digest = governance.policyDigest(policyId, version);

        var blocked = governance.publishPolicy(policyId, version, "release-owner");
        assertFalse(blocked.published());
        assertTrue(blocked.reason().contains("answer-key"));
        assertTrue(blocked.reason().contains("precision"));
        assertFalse(governance.releaseReadiness(policyId, version).ready());

        var environment = governance.createEnvironment(new EnvironmentCommand(
                "bedrock-agent-release", "2026.08.1", "AWS", "BEDROCK_AGENTS",
                "collector-owner", "security-reviewer", Map.of("bedrock", "2026-07-01"),
                Map.of("providerCallBudget", 100, "byteBudget", 1_000_000),
                "Candidate policy validation", Instant.now().plus(30, ChronoUnit.DAYS)), "release-owner");

        var secureCase = governance.addCase(environment.id(), new CaseCommand(
                "secure-guardrail", "SECURE", policyId, version, "APPLICABLE", "PASS", false,
                expected("PASS", false, "CONFIGURED"),
                "1", "Secure variant should pass", "answer-key://bedrock/secure"), "collector-owner");
        var insecureCase = governance.addCase(environment.id(), new CaseCommand(
                "missing-guardrail", "INSECURE", policyId, version, "APPLICABLE", "FAIL", true,
                expected("FAIL", true, "CONFIGURED"),
                "1", "Insecure variant should fail", "answer-key://bedrock/insecure"), "collector-owner");
        var proxyCase = governance.addCase(environment.id(), new CaseCommand(
                "configured-is-not-verified", "PROXY_VS_VERIFIED", policyId, version,
                "APPLICABLE", "NO_DECISION", false, expected("NO_DECISION", false, "PROXY_ONLY"),
                "1", "Configured access cannot satisfy verified reachability",
                "answer-key://bedrock/proxy-vs-verified"), "collector-owner");

        var certified = governance.certifyEnvironment(environment.id(), "security-reviewer");
        assertEquals("CERTIFIED", certified.lifecycle());
        assertThrows(ResponseStatusException.class, () -> governance.addCase(environment.id(), new CaseCommand(
                "late-case", "OTHER", null, null, null, null, null, Map.of("late", true),
                "1", "Must be immutable", "answer-key://late"), "collector-owner"));

        ProvenanceFixture provenance = seedProvenanceRun(policyId, version);
        assertThrows(ResponseStatusException.class, () -> governance.recordRun(environment.id(),
                new RunCommand(provenance.tenantId(), provenance.runId(), digest, Instant.now(), List.of(
                        new ResultCommand(secureCase.caseKey(), UUID.randomUUID(),
                                expected("PASS", false, "CONFIGURED"), null),
                        new ResultCommand(insecureCase.caseKey(), provenance.failAssessmentId(),
                                expected("FAIL", true, "CONFIGURED"), null),
                        new ResultCommand(proxyCase.caseKey(), provenance.noDecisionAssessmentId(),
                                expected("NO_DECISION", false, "PROXY_ONLY"), null))), "answer-key-runner"));

        var run = governance.recordRun(environment.id(), new RunCommand(
                provenance.tenantId(), provenance.runId(), digest, Instant.now(), List.of(
                new ResultCommand(secureCase.caseKey(), provenance.passAssessmentId(),
                        expected("PASS", false, "CONFIGURED"), null),
                new ResultCommand(insecureCase.caseKey(), provenance.failAssessmentId(),
                        expected("FAIL", true, "CONFIGURED"), null),
                new ResultCommand(proxyCase.caseKey(), provenance.noDecisionAssessmentId(),
                        expected("NO_DECISION", false, "PROXY_ONLY"), null)
        )), "answer-key-runner");
        assertEquals("PASS", run.status());
        assertEquals(3, run.matchedCases());
        assertEquals("PLATFORM_RUN_BOUND", run.provenanceState());
        assertEquals(provenance.runId(), run.sourceRunId());

        var review = governance.createPrecisionReview(new PrecisionReviewCommand(
                policyId, version,
                "All candidate findings stratified by AWS account, region, and agent guardrail state",
                "Deterministic stratified sample across secure and insecure answer-key populations",
                100, 0.95, 0.95), "precision-owner");
        for (int index = 1; index <= 100; index++) {
            var sample = governance.addPrecisionSample(review.id(), precisionSample(
                    "finding-" + index, policyId, version, provenance, 100 + index));
            labelTruePositive(review.id(), sample.id());
        }
        governance.assessBias(review.id(), true,
                "Population and sample cover the declared provider, family, severity, and outcome strata",
                "security-reviewer");
        var finalized = governance.finalizePrecisionReview(review.id());
        assertEquals("PASSED", finalized.status());
        assertEquals(1.0, finalized.precisionValue());
        assertNotNull(finalized.confidenceLower());
        assertNotNull(finalized.confidenceUpper());

        var ready = governance.releaseReadiness(policyId, version);
        assertTrue(ready.ready());
        assertEquals(run.id(), ready.answerKeyRunId());
        assertEquals(review.id(), ready.precisionReviewId());

        var released = governance.publishPolicy(policyId, version, "release-owner");
        assertTrue(released.published());
        assertEquals(run.id(), released.answerKeyRunId());
        assertEquals(review.id(), released.precisionReviewId());
        assertEquals("PUBLISHED", TenantContext.runAsPlatform(() -> jdbc.queryForObject("""
                select lifecycle from platform.ai_grid_policy_versions
                 where policy_id = :policyId and version = :version
                """, Map.of("policyId", policyId, "version", version), String.class)));
        assertEquals(2, TenantContext.runAsPlatform(() -> jdbc.queryForObject("""
                select count(*) from platform.ai_grid_policy_release_decisions
                 where policy_id = :policyId and policy_version = :version
                """, Map.of("policyId", policyId, "version", version), Integer.class)));
        assertEquals("APPROVED", governance.releaseReadiness(policyId, version).latestDecision());
    }

    @Test
    void rejectsUnderpoweredPerfectPrecisionWhenWilsonLowerBoundMissesThreshold() {
        String policyId = "GOVERNANCE_UNDERPOWERED_POLICY";
        ProvenanceFixture provenance = seedProvenanceRun(policyId, "1.0.0");
        var review = governance.createPrecisionReview(new PrecisionReviewCommand(
                policyId, "1.0.0", "Two reviewed findings", "Deterministic sample",
                2, 0.95, 0.95), "precision-owner");
        for (int index = 1; index <= 2; index++) {
            var sample = governance.addPrecisionSample(review.id(), precisionSample(
                    "underpowered-" + index, policyId, "1.0.0", provenance, 200 + index));
            labelTruePositive(review.id(), sample.id());
        }
        governance.assessBias(review.id(), true, "The declared two-item sample was reviewed as specified",
                "security-reviewer");

        var finalized = governance.finalizePrecisionReview(review.id());

        assertEquals("FAILED", finalized.status());
        assertEquals(1.0, finalized.precisionValue());
        assertTrue(finalized.confidenceLower() < finalized.precisionThreshold());
    }

    @Test
    void phaseOneLowSeverityPoliciesStillRequireFreshPrecisionReview() {
        var readiness = governance.releaseReadiness("GOVERNANCE_PHASE1_LOW_POLICY", "1.0.0");

        assertFalse(readiness.ready());
        assertTrue(readiness.blockers().contains("FRESH_PASSING_ANSWER_KEY_REQUIRED"));
        assertTrue(readiness.blockers().contains("PASSING_PRECISION_REVIEW_REQUIRED"));
    }

    private void labelTruePositive(UUID reviewId, UUID sampleId) {
        governance.submitLabel(reviewId, sampleId, new LabelCommand(
                "TRUE_POSITIVE", "1", "Evidence supports the finding", "review://evidence/" + sampleId),
                "reviewer-one");
        governance.submitLabel(reviewId, sampleId, new LabelCommand(
                "TRUE_POSITIVE", "1", "Independent evidence review agrees", "review://evidence/" + sampleId),
                "reviewer-two");
    }

    private ProvenanceFixture seedProvenanceRun(String policyId, String policyVersion) {
        Tenant tenant = tenantService.createTenant("Governance evidence " + UUID.randomUUID(),
                "governance-evidence-" + UUID.randomUUID(), "pilot", null);
        tenantSchemaMigrationService.provisionNewTenant(tenant);
        UUID runId = UUID.randomUUID();
        UUID pass = seedAssessment(tenant, runId, policyId, policyVersion, "PASS", false, 1);
        UUID fail = seedAssessment(tenant, runId, policyId, policyVersion, "FAIL", true, 2);
        UUID noDecision = seedAssessment(tenant, runId, policyId, policyVersion, "NO_DECISION", false, 3);
        return new ProvenanceFixture(tenant, runId, pass, fail, noDecision);
    }

    private PrecisionSampleCommand precisionSample(String sampleKey, String policyId, String policyVersion,
                                                    ProvenanceFixture provenance, int ordinal) {
        UUID assessmentId = seedAssessment(provenance.tenant(), provenance.runId(), policyId, policyVersion,
                "FAIL", true, ordinal);
        return new PrecisionSampleCommand(sampleKey, "AWS", "BEDROCK_AGENTS", "HIGH", "FAIL", true,
                "review://" + sampleKey, provenance.tenantId(), provenance.runId(), assessmentId);
    }

    private UUID seedAssessment(Tenant tenant, UUID runId, String policyId, String policyVersion,
                                String decision, boolean finding, int ordinal) {
        return tenantExecution.run(tenant, () -> {
            UUID artifactId = UUID.randomUUID();
            UUID bodyId = UUID.randomUUID();
            UUID manifestId = UUID.randomUUID();
            UUID assessmentId = UUID.randomUUID();
            String decisionFingerprint = String.format("%064d", ordinal);
            jdbc.update("""
                    insert into ai_security_artifacts
                        (id, tenant_id, provider, provider_resource_id, artifact_type, native_kind,
                         name, account_id, region, attributes_json, first_observed_at, last_observed_at)
                    values (:id, :tenantId, 'AWS', :resourceId, 'AI_AGENT', 'AWS_BEDROCK_AGENT',
                            :name, '123456789012', 'us-east-1', '{}'::jsonb, now(), now())
                    """, Map.of("id", artifactId, "tenantId", tenant.getId(),
                    "resourceId", "answer-key://agent/" + ordinal, "name", "Answer key agent " + ordinal));
            jdbc.update("""
                    insert into ai_grid_snapshot_bodies
                        (id, tenant_id, content_hash, content_json, byte_size, redaction_profile, first_run_id)
                    values (:id, :tenantId, :hash,
                            jsonb_build_object('artifactType','AI_AGENT','nativeKind','AWS_BEDROCK_AGENT'),
                            64, 'STANDARD_V1', :runId)
                    """, Map.of("id", bodyId, "tenantId", tenant.getId(),
                    "hash", String.format("%064x", ordinal), "runId", runId));
            jdbc.update("""
                    insert into ai_grid_snapshot_manifests
                        (id, tenant_id, run_id, artifact_id, scope_key, body_id, schema_version, observed_at)
                    values (:id, :tenantId, :runId, :artifactId, :scope, :bodyId, '1.0.0', now())
                    """, Map.of("id", manifestId, "tenantId", tenant.getId(), "runId", runId,
                    "artifactId", artifactId, "scope", "answer-key-scope-" + ordinal, "bodyId", bodyId));
            jdbc.update("""
                    insert into ai_grid_assessments
                        (id, tenant_id, run_id, policy_id, policy_version, subject_type, subject_id,
                         snapshot_manifest_id, selection, applicability, evidence_readiness, decision,
                         reason_code, fingerprint, evaluation_as_of, decision_fingerprint)
                    values (:id, :tenantId, :runId, :policyId, :version, 'ARTIFACT', :artifactId,
                            :manifestId, 'PREVIEW', 'APPLICABLE', 'READY', :decision,
                            'ANSWER_KEY', :fingerprint, now(), :decisionFingerprint)
                    """, Map.of("id", assessmentId, "tenantId", tenant.getId(), "runId", runId,
                    "policyId", policyId, "version", policyVersion, "artifactId", artifactId,
                    "manifestId", manifestId, "decision", decision,
                    "fingerprint", String.format("%064x", 100 + ordinal),
                    "decisionFingerprint", decisionFingerprint));
            if (finding) {
                jdbc.update("""
                        insert into findings
                            (id, tenant_id, created_at, updated_at, creation_source, display_id, matched_by,
                             risk_score, status, finding_kind, fingerprint, workflow_class, title,
                             policy_id, policy_version, reason_code, assessment_id)
                        values (:id, :tenantId, now(), now(), 'AI_SECURITY', :displayId, 'AI_GRID',
                                8.0, 'OPEN', 'AI_POSTURE', :fingerprint, 'POSTURE_FINDING',
                                'Answer key finding', :policyId, :version, 'ANSWER_KEY', :assessmentId)
                        """, Map.of("id", UUID.randomUUID(), "tenantId", tenant.getId(),
                        "displayId", "AK-" + ordinal, "fingerprint", String.format("%064x", 200 + ordinal),
                        "policyId", policyId, "version", policyVersion, "assessmentId", assessmentId));
            }
            return assessmentId;
        });
    }

    private record ProvenanceFixture(Tenant tenant, UUID runId, UUID passAssessmentId,
                                     UUID failAssessmentId, UUID noDecisionAssessmentId) {
        UUID tenantId() {
            return tenant.getId();
        }
    }

    private Map<String, Object> expected(String decision, boolean finding, String evidenceState) {
        return Map.of(
                "inventory", List.of("AWS_BEDROCK_AGENT"),
                "technologies", List.of("AWS_BEDROCK"),
                "capabilities", List.of("AGENT_ORCHESTRATION"),
                "facts", Map.of("evidenceState", evidenceState),
                "relationships", List.of("USES_GUARDRAIL"),
                "applicability", "APPLICABLE",
                "decisions", decision,
                "findings", finding,
                "gaps", "NO_DECISION".equals(decision) ? List.of("VERIFIED_REACHABILITY_MISSING") : List.of(),
                "closureTransitions", List.of("OPEN_TO_RESOLVED"));
    }
}
