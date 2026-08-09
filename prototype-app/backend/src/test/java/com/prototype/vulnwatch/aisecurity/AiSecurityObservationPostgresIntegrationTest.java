package com.prototype.vulnwatch.aisecurity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.reset;

import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ArtifactObservation;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ObservationEnvelopeV1;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.RelationshipObservation;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ScopeStatus;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAwsConnectorService;
import com.prototype.vulnwatch.aisecurity.service.AiGridOwnershipService;
import com.prototype.vulnwatch.aisecurity.service.AiGridApiService;
import com.prototype.vulnwatch.aisecurity.service.AiGridBudgetService;
import com.prototype.vulnwatch.aisecurity.service.AiGridCoverageService;
import com.prototype.vulnwatch.aisecurity.service.AiGridRetentionService;
import com.prototype.vulnwatch.aisecurity.service.AiGridSystemService;
import com.prototype.vulnwatch.aisecurity.service.AiGridReconciliationService;
import com.prototype.vulnwatch.aisecurity.service.AiGridRunMetricsService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityObservationService;
import com.prototype.vulnwatch.aisecurity.service.AiSecuritySyncRunFacade;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.FindingWorkflowUpdateRequest;
import com.prototype.vulnwatch.service.FindingDeltaQueueService;
import com.prototype.vulnwatch.service.IngestionJobWorkerService;
import com.prototype.vulnwatch.service.FindingWorkflowService;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;

@PostgresIntegrationTest
@TestPropertySource(properties = "spring.main.allow-circular-references=true")
class AiSecurityObservationPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("ai_security_observations");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private TenantService tenantService;
    @Autowired private TenantSchemaMigrationService tenantSchemaMigrationService;
    @Autowired private TenantSchemaExecutionService tenantExecution;
    @Autowired private AiSecurityAwsConnectorService connectorService;
    @Autowired private AiSecurityObservationService observationService;
    @Autowired private AiGridOwnershipService ownershipService;
    @Autowired private AiGridApiService aiGridApiService;
    @Autowired private com.prototype.vulnwatch.aisecurity.service.AiSecurityApiService aiSecurityApiService;
    @Autowired private AiGridBudgetService budgetService;
    @Autowired private AiGridCoverageService coverageService;
    @Autowired private AiGridRetentionService retentionService;
    @Autowired private AiGridSystemService systemService;
    @Autowired private AiGridRunMetricsService runMetricsService;
    @Autowired private FindingWorkflowService findingWorkflowService;
    @Autowired private AiSecuritySyncRunFacade syncRunFacade;
    @Autowired private NamedParameterJdbcTemplate jdbc;

    @SpyBean private AiGridReconciliationService reconciliationService;

    @MockBean private IngestionJobWorkerService ingestionJobWorkerService;
    @MockBean private FindingDeltaQueueService findingDeltaQueueService;

    @Test
    void enforcesReplayAndSnapshotCompletenessWithinTenantBoundary() {
        Tenant tenant = provision("AI Security Co", "ai-security-co");
        UUID connectorId = connectorService.save(
                tenant,
                new AiSecurityAwsConnectorService.ConnectorConfigRequest(
                        "123456789012", null, null, List.of("us-east-1"), true)
        ).id();

        UUID firstRun = syncRunFacade.start(tenant).getId();
        ObservationEnvelopeV1 first = envelope(
                tenant, connectorId, firstRun, "hash-1", ScopeStatus.COMPLETE,
                List.of(new ArtifactObservation(
                        "arn:aws:bedrock:us-east-1:123456789012:agent/agent-1",
                        "AI_AGENT",
                        "AWS_BEDROCK_AGENT",
                        "Support agent",
                        Map.of("iamWildcardActions", false))));

        var accepted = observationService.ingest(tenant, first);
        var duplicate = observationService.ingest(tenant, first);

        assertEquals(ScopeStatus.COMPLETE, accepted.scopeStatus());
        assertTrue(duplicate.duplicate());
        assertThrows(IllegalArgumentException.class, () ->
                observationService.ingest(
                        tenant,
                        envelope(tenant, connectorId, firstRun, "different-hash",
                                ScopeStatus.COMPLETE, first.artifacts())));
        assertEquals(1, activeArtifacts(tenant));
        assertEquals(1, observationService.countPersistedArtifacts(tenant, firstRun));

        UUID partialRun = syncRunFacade.start(tenant).getId();
        observationService.ingest(
                tenant,
                envelope(tenant, connectorId, partialRun, "hash-2", ScopeStatus.PARTIAL, List.of()));
        assertEquals(1, activeArtifacts(tenant), "partial scope must retain previously observed inventory");

        UUID completeRun = syncRunFacade.start(tenant).getId();
        observationService.ingest(
                tenant,
                envelope(tenant, connectorId, completeRun, "hash-3", ScopeStatus.COMPLETE, List.of()));
        assertEquals(0, activeArtifacts(tenant), "complete empty scope may deactivate missing inventory");

        Tenant otherTenant = provision("Other AI Co", "other-ai-co");
        ObservationEnvelopeV1 mismatched = envelope(
                otherTenant, connectorId, firstRun, "hash-4", ScopeStatus.COMPLETE, List.of());
        assertThrows(IllegalArgumentException.class, () -> observationService.ingest(otherTenant, mismatched));
    }

    @Test
    void requiresRegionalAgentAndAccountGlobalIamScopesBeforePolicyDecision() {
        Tenant tenant = provision("Scope Semantics Co", "scope-semantics-co");
        UUID connectorId = connectorService.save(
                tenant,
                new AiSecurityAwsConnectorService.ConnectorConfigRequest(
                        "123456789012", null, null, List.of("us-east-1"), true)
        ).id();
        UUID runId = syncRunFacade.start(tenant).getId();
        ArtifactObservation agent = new ArtifactObservation(
                "arn:aws:bedrock:us-east-1:123456789012:agent/scope-agent",
                "AI_AGENT",
                "AWS_BEDROCK_AGENT",
                "Scope agent",
                Map.of("iamWildcardActions", true));

        observationService.ingest(
                tenant,
                evidenceEnvelope(
                        tenant, connectorId, runId, "us-east-1", "BEDROCK_AGENTS", "agent-scope", List.of(agent)));
        assertEquals("NO_DECISION", wildcardRoleOutcome(tenant, runId));

        observationService.ingest(
                tenant,
                evidenceEnvelope(
                        tenant, connectorId, runId, "us-east-1", "IAM_GLOBAL", "mis-tagged-iam", List.of()));
        assertEquals(
                "NO_DECISION",
                wildcardRoleOutcome(tenant, runId),
                "regional IAM evidence must not satisfy an account-global requirement");

        observationService.ingest(
                tenant,
                evidenceEnvelope(
                        tenant, connectorId, runId, "GLOBAL", "IAM_GLOBAL", "global-iam", List.of()));
        assertEquals("FAIL", wildcardRoleOutcome(tenant, runId));
    }

    @Test
    void hashesEvidenceIdentityForLongProviderResourceIds() {
        Tenant tenant = provision("Long Resource Co", "long-resource-co");
        UUID connectorId = connectorService.save(
                tenant,
                new AiSecurityAwsConnectorService.ConnectorConfigRequest(
                        "123456789012", null, null, List.of("us-east-1"), true)
        ).id();
        UUID runId = syncRunFacade.start(tenant).getId();
        String providerResourceId = "/subscriptions/" + "a".repeat(220);

        observationService.ingest(
                tenant,
                envelope(
                        tenant,
                        connectorId,
                        runId,
                        "f".repeat(64),
                        ScopeStatus.COMPLETE,
                        List.of(new ArtifactObservation(
                                providerResourceId,
                                "AI_MODEL",
                                "AZURE_OPENAI_DEPLOYMENT",
                                "Long Azure resource",
                                Map.of()))));

        Integer hashLength = tenantExecution.run(tenant, () -> jdbc.queryForObject(
                "select length(evidence_hash) from ai_security_artifact_sources",
                Map.of(),
                Integer.class));
        assertEquals(64, hashLength);
    }

    @Test
    void buildsMinimumContextPackAndFirstRunReadinessWithoutShrinkingCoverage() {
        Tenant tenant = provision("AI Grid context co", "ai-grid-context-co");
        UUID connectorId = connectorService.save(
                tenant,
                new AiSecurityAwsConnectorService.ConnectorConfigRequest(
                        "123456789012", null, null, List.of("us-east-1"), true)
        ).id();
        UUID runId = syncRunFacade.start(tenant).getId();
        tenantExecution.run(tenant, () -> jdbc.update("""
                insert into ownership_rules
                    (id, tenant_id, name, condition_json, user_group, execution_order, created_at, updated_at)
                values (:id, :tenantId, 'AWS AI ownership',
                        '{"logic":"AND","conditions":[{"table":"ASSET","column":"cloudProvider","operator":"is","value":"AWS"}]}',
                        'Cloud AI Team', 10, now(), now())
                """, Map.of("id", UUID.randomUUID(), "tenantId", tenant.getId())));
        ArtifactObservation agent = new ArtifactObservation(
                "arn:aws:bedrock:us-east-1:123456789012:agent/context-agent",
                "AI_AGENT", "AWS_BEDROCK_AGENT", "Context agent",
                Map.of("iamWildcardActions", false, "tags", Map.of("owner", "AI Platform")));
        ArtifactObservation knowledgeBase = new ArtifactObservation(
                "arn:aws:bedrock:us-east-1:123456789012:knowledge-base/context-kb",
                "KNOWLEDGE_BASE", "AWS_BEDROCK_KNOWLEDGE_BASE", "Context knowledge base", Map.of());
        observationService.ingest(tenant, new ObservationEnvelopeV1(
                AiSecurityObservationService.CONTRACT_VERSION, runId, connectorId, tenant.getId(), "AWS",
                "123456789012", "us-east-1", "BEDROCK_AGENTS",
                "AWS:123456789012:us-east-1:BEDROCK_AGENTS", 0, 1,
                runId + ":context:0", "context-hash", Instant.now(), ScopeStatus.COMPLETE,
                List.of(agent, knowledgeBase), List.of(new RelationshipObservation(
                        agent.providerResourceId(), knowledgeBase.providerResourceId(),
                        "USES_KNOWLEDGE_BASE", Map.of())), List.of()));

        tenantExecution.run(tenant, () -> {
            assertEquals("INFERRED", jdbc.queryForObject("""
                    select owner_state from ai_security_artifacts where native_kind = 'AWS_BEDROCK_AGENT'
                    """, Map.of(), String.class));
            assertEquals("Cloud AI Team", jdbc.queryForObject("""
                    select owner_name from ai_security_artifacts where native_kind = 'AWS_BEDROCK_AGENT'
                    """, Map.of(), String.class));
            assertEquals(true, jdbc.queryForObject("""
                    select value_json = 'true'::jsonb from ai_grid_facts f
                      join ai_security_artifacts a on a.id = f.artifact_id
                     where f.run_id = :runId and f.fact_key = 'data.source_linked'
                       and a.native_kind = 'AWS_BEDROCK_AGENT'
                    """, Map.of("runId", runId), Boolean.class));
            assertEquals("DERIVED", jdbc.queryForObject("""
                    select provenance from ai_grid_facts where run_id = :runId
                     and fact_key = 'data.source_linked'
                    """, Map.of("runId", runId), String.class));
            assertEquals("RELATIONSHIP_GRAPH", jdbc.queryForObject("""
                    select evidence_class from ai_grid_facts where run_id = :runId
                     and fact_key = 'data.source_linked'
                    """, Map.of("runId", runId), String.class));
            assertEquals(0, jdbc.queryForObject("""
                    select count(*) from ai_grid_facts where run_id = :runId
                     and fact_key = 'data.sensitive_content_confirmed'
                    """, Map.of("runId", runId), Integer.class),
                    "a linked source must not be promoted to confirmed sensitive content");
            return null;
        });
        assertEquals(8, TenantContext.runAsPlatform(() -> jdbc.queryForObject("""
                select count(*) from platform.ai_grid_fact_definitions where fact_key in (
                    'network.public_access_configured','network.internet_reachability_verified',
                    'identity.wildcard_permission_observed','identity.effective_admin_access_derived',
                    'data.source_linked','data.sensitive_content_confirmed',
                    'owner.tag_candidate','owner.confirmed')
                """, Map.of(), Integer.class)));

        var readiness = aiGridApiService.policyReadiness(tenant);
        var wildcard = readiness.stream()
                .filter(item -> "AWS_BEDROCK_WILDCARD_AGENT_ROLE".equals(item.policyId()))
                .findFirst().orElseThrow();
        assertEquals("BLOCKED", wildcard.readiness());
        assertTrue(wildcard.missingEvidenceJson().contains("IAM_GLOBAL"));

        var actions = aiGridApiService.setupActions(tenant);
        assertTrue(actions.stream().anyMatch(action -> "RESTORE_SCOPE_ACCESS".equals(action.actionCode())));
        for (int index = 1; index < actions.size(); index++) {
            assertTrue(actions.get(index - 1).priority() <= actions.get(index).priority());
        }

        var coverage = aiGridApiService.coverage(tenant);
        var metrics = aiGridApiService.runMetrics(tenant, runId);
        assertEquals(coverage.expectedAssessments(), metrics.expectedAssessmentCount());
        assertEquals(coverage.missingAssessments(), metrics.missingAssessmentCount());
        assertEquals(connectorId, metrics.connectorConfigId());
        assertEquals(true, metrics.baselineRun());
        assertEquals(80.0, metrics.firstRunTargetPercent());
        assertEquals(metrics.ownerFacingDecisionCount() * 100.0 / metrics.ownerFacingExpectedCount(),
                metrics.ownerFacingUtilityPercent(), 0.01);
        assertEquals(metrics.ownerFacingUtilityPercent() >= metrics.firstRunTargetPercent(),
                metrics.firstRunTargetMet());
    }

    @Test
    void aiGridR0CreatesImmutableFactsAssessmentSystemAndCanonicalFinding() {
        Tenant tenant = provision("AI Grid R0 Co", "ai-grid-r0-co");
        UUID connectorId = connectorService.save(
                tenant,
                new AiSecurityAwsConnectorService.ConnectorConfigRequest(
                        "123456789012", null, null, List.of("us-east-1"), true)
        ).id();
        UUID runId = syncRunFacade.start(tenant).getId();
        ArtifactObservation agent = new ArtifactObservation(
                "arn:aws:bedrock:us-east-1:123456789012:agent/r0-agent",
                "AI_AGENT", "AWS_BEDROCK_AGENT", "R0 agent",
                Map.of(
                        "guardrailAttached", true,
                        "guardrailMinimumStrength", "LOW",
                        "tags", Map.of("team", "AI Platform Team")));
        ArtifactObservation guardrail = new ArtifactObservation(
                "arn:aws:bedrock:us-east-1:123456789012:guardrail/r0-guardrail",
                "GUARDRAIL", "AWS_BEDROCK_GUARDRAIL", "R0 guardrail", Map.of());
        String agentScope = "AWS:123456789012:us-east-1:BEDROCK_AGENTS";
        observationService.ingest(tenant, new ObservationEnvelopeV1(
                AiSecurityObservationService.CONTRACT_VERSION, runId, connectorId, tenant.getId(), "AWS",
                "123456789012", "us-east-1", "BEDROCK_AGENTS", agentScope, 0, 1,
                runId + ":agents:0", "agent-hash", Instant.now(), ScopeStatus.COMPLETE,
                List.of(agent, guardrail), List.of(new RelationshipObservation(
                        agent.providerResourceId(), guardrail.providerResourceId(), "USES_GUARDRAIL", Map.of())), List.of()));

        String guardrailScope = "AWS:123456789012:us-east-1:BEDROCK_GUARDRAILS";
        observationService.ingest(tenant, new ObservationEnvelopeV1(
                AiSecurityObservationService.CONTRACT_VERSION, runId, connectorId, tenant.getId(), "AWS",
                "123456789012", "us-east-1", "BEDROCK_GUARDRAILS", guardrailScope, 0, 1,
                runId + ":guardrails:0", "guardrail-hash", Instant.now(), ScopeStatus.COMPLETE,
                List.of(guardrail), List.of(), List.of()));

        Map<String, String> originalFingerprints = tenantExecution.run(tenant, () -> {
            assertEquals(3, jdbc.queryForObject(
                    "select count(*) from ai_grid_snapshot_manifests where run_id = :runId",
                    Map.of("runId", runId), Integer.class));
            assertEquals(2, jdbc.queryForObject(
                    "select count(*) from ai_grid_snapshot_bodies",
                    Map.of(), Integer.class),
                    "the same guardrail evidence in two manifests must reuse one content-addressed body");
            assertEquals(3, jdbc.queryForObject(
                    "select count(*) from ai_grid_facts where run_id = :runId",
                    Map.of("runId", runId), Integer.class));
            assertEquals("FAIL", jdbc.queryForObject("""
                    select decision from ai_grid_assessments
                     where run_id = :runId and policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL'
                    """, Map.of("runId", runId), String.class));
            assertEquals(1, jdbc.queryForObject("select count(*) from ai_grid_systems", Map.of(), Integer.class));
            jdbc.update("""
                    update ai_security_relationships set active = false
                     where relationship_type = 'USES_GUARDRAIL'
                    """, Map.of());
            systemService.deriveForRun(tenant, runId);
            assertEquals(1, jdbc.queryForObject("select count(*) from ai_grid_system_revisions", Map.of(), Integer.class),
                    "re-deriving a run must use its relationship snapshot, not changed live relationships");
            assertEquals(1, jdbc.queryForObject(
                    "select count(*) from findings where finding_kind = 'AI_POSTURE' and status = 'OPEN'",
                    Map.of(), Integer.class));
            assertEquals(0, jdbc.queryForObject(
                    "select count(*) from ai_security_findings", Map.of(), Integer.class),
                    "legacy findings silo stays empty by default; AI findings graduate to the host workflow");
            assertTrue(jdbc.queryForObject("""
                    select due_at is not null from findings where finding_kind = 'AI_POSTURE'
                    """, Map.of(), Boolean.class));
            assertEquals(1, jdbc.queryForObject("""
                    select count(*) from finding_events where event_type = 'CREATED_BY_AI_ASSESSMENT'
                    """, Map.of(), Integer.class));
            assertEquals(1, jdbc.queryForObject("select count(*) from finding_subjects", Map.of(), Integer.class));
            assertEquals("CANDIDATE", jdbc.queryForObject("""
                    select owner_state from ai_security_artifacts where native_kind = 'AWS_BEDROCK_AGENT'
                    """, Map.of(), String.class));
            assertNull(jdbc.queryForObject("""
                    select owner_group from findings where finding_kind = 'AI_POSTURE'
                    """, Map.of(), String.class));
            assertEquals(2, jdbc.queryForObject("""
                    select completed_scope_count from ai_grid_run_metrics where run_id = :runId
                    """, Map.of("runId", runId), Integer.class));
            assertEquals("UNAVAILABLE", jdbc.queryForObject("""
                    select provider_call_measurement_state from ai_grid_run_metrics where run_id = :runId
                    """, Map.of("runId", runId), String.class));
            assertTrue(jdbc.queryForObject("""
                    select new_snapshot_bytes > 0 from ai_grid_run_metrics where run_id = :runId
                    """, Map.of("runId", runId), Boolean.class));
            UUID agentId = jdbc.queryForObject("""
                    select id from ai_security_artifacts where native_kind = 'AWS_BEDROCK_AGENT'
                    """, Map.of(), UUID.class);
            ownershipService.confirm(tenant, agentId, "AI Platform Team", "integration-reviewer",
                    "Answer-key owner confirmation");
            assertEquals("CONFIRMED", jdbc.queryForObject(
                    "select owner_state from ai_security_artifacts where id = :id", Map.of("id", agentId), String.class));
            assertEquals(0, jdbc.queryForObject("""
                    select count(*) from ai_grid_coverage_gaps where artifact_id = :id
                      and state = 'UNRESOLVED_OWNER' and status = 'OPEN'
                    """, Map.of("id", agentId), Integer.class));
            assertEquals("AI Platform Team", jdbc.queryForObject("""
                    select owner_group from findings where finding_kind = 'AI_POSTURE'
                    """, Map.of(), String.class));

            runMetricsService.recordProviderCalls(tenant, runId, "AWS", 17);
            assertEquals("MEASURED", jdbc.queryForObject("""
                    select provider_call_measurement_state from ai_grid_run_metrics where run_id = :runId
                    """, Map.of("runId", runId), String.class));
            assertEquals(17L, jdbc.queryForObject("""
                    select provider_api_calls from ai_grid_run_metrics where run_id = :runId
                    """, Map.of("runId", runId), Long.class));

            var cadence = new AiGridBudgetService.CadenceCommand(
                    "AWS", "BEDROCK_AGENTS", "PRODUCTION", "HIGH", 3600, true,
                    "Prevent redundant provider scans");
            budgetService.update(tenant, new AiGridBudgetService.BudgetConfigCommand(
                    "THROTTLE", 10L, null, null, null, null, 0.8,
                    "Integration cadence gate"), "integration-reviewer");
            budgetService.upsertCadence(tenant, cadence, "integration-reviewer");
            budgetService.admit(tenant, runId, "AWS", List.of("BEDROCK_AGENTS"), "PRODUCTION", "HIGH");
            assertEquals("ADMITTED", budgetService.admit(tenant, runId, "AWS",
                    List.of("BEDROCK_AGENTS"), "PRODUCTION", "HIGH").decision(),
                    "an admission retry must return the persisted decision");
            var cadenceError = assertThrows(AiGridBudgetService.BudgetExceededException.class,
                    () -> budgetService.admit(tenant, UUID.randomUUID(), "AWS",
                            List.of("BEDROCK_AGENTS"), "PRODUCTION", "HIGH"));
            assertEquals("CADENCE_NOT_DUE", cadenceError.getMessage());
            budgetService.upsertCadence(tenant, new AiGridBudgetService.CadenceCommand(
                    "AWS", "BEDROCK_AGENTS", "PRODUCTION", "HIGH", 3600, false,
                    "Disable cadence to isolate hard budget test"), "integration-reviewer");

            budgetService.update(tenant, new AiGridBudgetService.BudgetConfigCommand(
                    "THROTTLE", 1L, null, null, null, null, 0.8,
                    "Integration budget gate"), "integration-reviewer");
            assertThrows(AiGridBudgetService.BudgetExceededException.class, () -> budgetService.admit(
                    tenant, UUID.randomUUID(), "AWS", List.of("BEDROCK_AGENTS"), "PRODUCTION", "HIGH"));
            assertEquals(1, jdbc.queryForObject("""
                    select count(*) from ai_grid_budget_alerts
                     where metric = 'DAILY_SCANS' and level = 'EXCEEDED' and status = 'OPEN'
                    """, Map.of(), Integer.class));

            UUID guardrailBodyId = jdbc.queryForObject("""
                    select b.id from ai_grid_snapshot_bodies b
                      join ai_grid_snapshot_manifests m on m.body_id = b.id
                      join ai_security_artifacts a on a.id = m.artifact_id
                     where a.native_kind = 'AWS_BEDROCK_GUARDRAIL' limit 1
                    """, Map.of(), UUID.class);
            jdbc.update("""
                    insert into ai_grid_snapshot_bodies
                        (id, tenant_id, content_hash, content_json, byte_size, redaction_profile,
                         first_run_id, retention_class, retain_until, retention_state)
                    values (:id, :tenantId, :hash, '{}'::jsonb, 2, 'STANDARD', :runId,
                            'ARCHIVE', now() - interval '1 day', 'RETAINED')
                    """, Map.of("id", UUID.randomUUID(), "tenantId", tenant.getId(),
                    "hash", "f".repeat(64), "runId", runId));
            var hold = retentionService.createHold(tenant, new AiGridRetentionService.HoldCommand(
                    guardrailBodyId, "LEGAL_HOLD", "legal-case-1",
                    "Preserve evidence for legal review", null), "integration-reviewer");
            jdbc.update("update ai_grid_snapshot_bodies set retain_until = now() - interval '1 day'", Map.of());
            var protectedSweep = retentionService.sweep(tenant);
            assertTrue(protectedSweep.purgeBlocked() >= 2);
            assertEquals(1, protectedSweep.purged(), "expired unreferenced evidence should be purged safely");
            assertEquals(1, jdbc.queryForObject("select count(*) from ai_grid_retention_purge_audit",
                    Map.of(), Integer.class));
            retentionService.releaseHold(tenant, hold.id(), "integration-reviewer");
            var releasedSweep = retentionService.sweep(tenant);
            assertTrue(releasedSweep.purgeEligible() >= 1);
            assertEquals("PURGE_BLOCKED", jdbc.queryForObject("""
                    select b.retention_state from ai_grid_snapshot_bodies b
                      join ai_grid_snapshot_manifests m on m.body_id = b.id
                      join ai_grid_assessments a on a.snapshot_manifest_id = m.id
                      join findings f on f.assessment_id = a.id
                     where f.status = 'OPEN' limit 1
                    """, Map.of(), String.class));
            return Map.of(
                    "finding", jdbc.queryForObject("""
                            select fingerprint from ai_grid_assessments
                             where run_id = :runId and policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL'
                            """, Map.of("runId", runId), String.class),
                    "decision", jdbc.queryForObject("""
                            select decision_fingerprint from ai_grid_assessments
                             where run_id = :runId and policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL'
                            """, Map.of("runId", runId), String.class));
        });

        UUID reviewedFindingId = tenantExecution.run(tenant, () -> jdbc.queryForObject(
                "select id from findings where finding_kind = 'AI_POSTURE'", Map.of(), UUID.class));
        aiSecurityApiService.review(tenant, reviewedFindingId,
                com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ReviewDisposition.FALSE_POSITIVE,
                "regression: review on the host finding model", "integration-reviewer");
        Integer hostReviewCount = tenantExecution.run(tenant, () -> jdbc.queryForObject("""
                select count(*) from finding_reviews where finding_id = :id and disposition = 'FALSE_POSITIVE'
                """, Map.of("id", reviewedFindingId), Integer.class));
        assertEquals(1, hostReviewCount,
                "AI finding review is recorded against the host finding model, not the legacy silo");

        var completeCoverage = aiGridApiService.coverage(tenant);
        jdbc.update("""
                insert into platform.ai_grid_policy_versions (
                    policy_id, version, name, description, severity, lifecycle, workflow_class,
                    default_selection, artifact_types_json, required_capabilities_json,
                    required_relationships_json, required_resource_families_json, required_facts_json,
                    predicate_json, reason_code, remediation, framework_mappings_json,
                    native_kinds_json, scope_resolution, published_at)
                select 'AI_GRID_COVERAGE_OMISSION_TEST', version, 'Coverage omission test', description,
                       severity, 'PUBLISHED', workflow_class, 'PREVIEW', artifact_types_json,
                       required_capabilities_json, required_relationships_json,
                       required_resource_families_json, required_facts_json, predicate_json,
                       'AI_GRID_COVERAGE_OMISSION', remediation, framework_mappings_json,
                       native_kinds_json, scope_resolution, now()
                  from platform.ai_grid_policy_versions
                 where policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL' and version = '2.0.0'
                on conflict do nothing
                """, Map.of());
        jdbc.update("""
                insert into platform.ai_grid_policy_distribution
                    (policy_id, available, default_selection, rollout_stage, updated_by)
                values ('AI_GRID_COVERAGE_OMISSION_TEST', true, 'PREVIEW', 'GENERAL_AVAILABILITY', 'integration-test')
                on conflict (policy_id) do update set
                    available = excluded.available,
                    default_selection = excluded.default_selection,
                    rollout_stage = excluded.rollout_stage,
                    updated_by = excluded.updated_by,
                    updated_at = now()
                """, Map.of());
        tenantExecution.run(tenant, () -> reconciliationService.reconcile(tenant, runId));
        tenantExecution.run(tenant, () -> {
            UUID epochId = coverageService.refreshCurrent(tenant, runId);
            reconciliationService.reconcileCurrent(tenant, epochId, runId);
            return null;
        });
        var incompleteCoverage = aiGridApiService.coverage(tenant);
        assertEquals(runId, incompleteCoverage.runId());
        assertEquals(completeCoverage.expectedAssessments() + 1, incompleteCoverage.expectedAssessments());
        assertEquals(completeCoverage.recordedAssessments(), incompleteCoverage.recordedAssessments());
        assertEquals(completeCoverage.missingAssessments() + 1, incompleteCoverage.missingAssessments());
        assertTrue(incompleteCoverage.decisionReachabilityPercent()
                < completeCoverage.decisionReachabilityPercent());
        assertEquals(completeCoverage.ownerFacingDecisionReachabilityPercent(),
                incompleteCoverage.ownerFacingDecisionReachabilityPercent());
        assertEquals("MISSING_ASSESSMENT", aiGridApiService.coverageDetails(tenant).stream()
                .filter(item -> "AI_GRID_COVERAGE_OMISSION_TEST".equals(item.policyId()))
                .findFirst().orElseThrow().gapState());
        assertEquals(1, tenantExecution.run(tenant, () -> jdbc.queryForObject("""
                select count(*) from ai_grid_coverage_gaps
                 where run_id = :runId and policy_id = 'AI_GRID_COVERAGE_OMISSION_TEST'
                   and state = 'MISSING_ASSESSMENT' and status = 'OPEN'
                """, Map.of("runId", runId), Integer.class)));
        aiGridApiService.replay(tenant, runId);
        assertEquals(0, aiGridApiService.coverage(tenant).missingAssessments());
        assertEquals(0, tenantExecution.run(tenant, () -> jdbc.queryForObject("""
                select count(*) from ai_grid_coverage_gaps
                 where policy_id = 'AI_GRID_COVERAGE_OMISSION_TEST'
                   and state = 'MISSING_ASSESSMENT' and status = 'OPEN'
                """, Map.of(), Integer.class)));
        jdbc.update("delete from platform.ai_grid_policy_versions where policy_id = 'AI_GRID_COVERAGE_OMISSION_TEST'",
                Map.of());

        tenantExecution.run(tenant, () -> {
            jdbc.update("update ai_grid_snapshot_manifests set observed_at = now() - interval '48 hours' where run_id = :runId",
                    Map.of("runId", runId));
            jdbc.update("update ai_grid_facts set observed_at = now() - interval '49 hours' where run_id = :runId",
                    Map.of("runId", runId));
            return null;
        });
        aiGridApiService.replay(tenant, runId);
        String agedDecisionFingerprint = tenantExecution.run(tenant, () -> {
            Map<String, Object> replayed = jdbc.queryForMap("""
                    select fingerprint, decision_fingerprint, decision,
                           evaluation_as_of = (select max(observed_at) from ai_grid_snapshot_manifests
                                                where run_id = :runId) as stable_as_of
                      from ai_grid_assessments
                     where run_id = :runId and policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL'
                    """, Map.of("runId", runId));
            assertEquals(originalFingerprints.get("finding"), replayed.get("fingerprint"));
            assertEquals("FAIL", replayed.get("decision"),
                    "wall-clock passage must not turn a replayed decision into stale evidence");
            assertEquals(true, replayed.get("stable_as_of"));
            return (String) replayed.get("decision_fingerprint");
        });
        aiGridApiService.replay(tenant, runId);
        tenantExecution.run(tenant, () -> {
            assertEquals(agedDecisionFingerprint, jdbc.queryForObject("""
                    select decision_fingerprint from ai_grid_assessments
                     where run_id = :runId and policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL'
                    """, Map.of("runId", runId), String.class),
                    "identical stored policy and fact material must reproduce the decision-content hash");
            return null;
        });

        Tenant isolatedTenant = provision("AI Grid R0 Isolated Co", "ai-grid-r0-isolated-co");
        assertEquals(0, tenantExecution.run(isolatedTenant, () -> jdbc.queryForObject(
                "select count(*) from ai_grid_snapshot_manifests", Map.of(), Integer.class)),
                "AI Grid evidence must remain isolated in the owning tenant schema");

        UUID findingId = tenantExecution.run(tenant, () -> jdbc.queryForObject(
                "select id from findings where finding_kind = 'AI_POSTURE'",
                Map.of(), UUID.class));
        tenantExecution.run(tenant, () -> findingWorkflowService.updateWorkflow(findingId,
                new FindingWorkflowUpdateRequest("SUPPRESSED", null, null, null,
                        "Approved investigation window", Instant.now().plus(1, ChronoUnit.DAYS),
                        "integration-reviewer")));

        UUID suppressedFailureRun = ingestR0Run(tenant, connectorId, "LOW", "suppressed-failure", true);
        tenantExecution.run(tenant, () -> {
            assertEquals("SUPPRESSED", jdbc.queryForObject(
                    "select status from findings where id = :id", Map.of("id", findingId), String.class));
            assertEquals(suppressedFailureRun, jdbc.queryForObject(
                    "select last_observed_run_id from findings where id = :id", Map.of("id", findingId), UUID.class));
            return null;
        });

        UUID remediationRun = ingestR0Run(tenant, connectorId, "MEDIUM", "verified-remediation", true);
        tenantExecution.run(tenant, () -> {
            assertEquals("RESOLVED", jdbc.queryForObject(
                    "select status from findings where id = :id", Map.of("id", findingId), String.class));
            assertEquals("VERIFIED_REMEDIATION", jdbc.queryForObject(
                    "select closed_reason from findings where id = :id", Map.of("id", findingId), String.class));
            assertEquals(remediationRun, jdbc.queryForObject(
                    "select last_observed_run_id from findings where id = :id", Map.of("id", findingId), UUID.class));
            assertEquals(1, jdbc.queryForObject("""
                    select count(*) from finding_events
                     where finding_id = :id and event_type = 'RESOLVED_BY_VERIFIED_REASSESSMENT'
                    """, Map.of("id", findingId), Integer.class));
            return null;
        });

        UUID recurrenceRun = ingestR0Run(tenant, connectorId, "LOW", "recurrence", true);
        tenantExecution.run(tenant, () -> {
            assertEquals("OPEN", jdbc.queryForObject(
                    "select status from findings where id = :id", Map.of("id", findingId), String.class));
            assertNull(jdbc.queryForObject(
                    "select closed_reason from findings where id = :id", Map.of("id", findingId), String.class));
            assertEquals(recurrenceRun, jdbc.queryForObject(
                    "select last_observed_run_id from findings where id = :id", Map.of("id", findingId), UUID.class));
            assertEquals(1, jdbc.queryForObject("""
                    select count(*) from finding_events
                     where finding_id = :id and event_type = 'REOPENED_BY_OBSERVATION'
                    """, Map.of("id", findingId), Integer.class));
            return null;
        });

        UUID incompleteRun = ingestR0Run(tenant, connectorId, "MEDIUM", "incomplete-remediation", false);
        tenantExecution.run(tenant, () -> {
            assertEquals("NO_DECISION", jdbc.queryForObject("""
                    select decision from ai_grid_assessments
                     where run_id = :runId and policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL'
                    """, Map.of("runId", incompleteRun), String.class));
            assertEquals("OPEN", jdbc.queryForObject(
                    "select status from findings where id = :id", Map.of("id", findingId), String.class));
            assertEquals(recurrenceRun, jdbc.queryForObject(
                    "select last_observed_run_id from findings where id = :id",
                    Map.of("id", findingId), UUID.class),
                    "incomplete evidence must not close or advance the canonical finding");
            return null;
        });

        try {
            jdbc.update("""
                    update platform.ai_grid_policy_versions
                       set required_facts_json = jsonb_set(required_facts_json, '{0,minConfidence}', '0.9'::jsonb)
                     where policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL' and version = '2.0.0'
                    """, Map.of());
            tenantExecution.run(tenant, () -> {
                jdbc.update("update ai_grid_facts set confidence = 0.5 where run_id = :runId",
                        Map.of("runId", recurrenceRun));
                assertEquals(0.9, jdbc.queryForObject("""
                        select (required_facts_json->0->>'minConfidence')::double precision
                          from platform.ai_grid_policy_versions
                         where policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL' and version = '2.0.0'
                        """, Map.of(), Double.class));
                assertEquals(0, jdbc.queryForObject("""
                        select count(*) from ai_grid_facts
                         where run_id = :runId and confidence is distinct from 0.5
                        """, Map.of("runId", recurrenceRun), Integer.class));
                assertTrue(jdbc.queryForObject("""
                        select count(*) > 0
                          from ai_grid_snapshot_manifests m
                          join ai_grid_snapshot_bodies b on b.id = m.body_id
                         where m.run_id = :runId
                           and b.content_json->>'artifactType' = 'AI_AGENT'
                           and b.content_json->>'nativeKind' = 'AWS_BEDROCK_AGENT'
                        """, Map.of("runId", recurrenceRun), Boolean.class));
                assertEquals(1, jdbc.queryForObject("""
                        select count(*) from platform.ai_grid_policy_versions
                         where policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL' and lifecycle = 'PUBLISHED'
                        """, Map.of(), Integer.class));
                jdbc.update("update ai_grid_assessments set evaluated_at = '2000-01-01' where run_id = :runId",
                        Map.of("runId", recurrenceRun));
                return null;
            });
            aiGridApiService.replay(tenant, recurrenceRun);
            tenantExecution.run(tenant, () -> {
                assertTrue(jdbc.queryForObject("""
                        select evaluated_at > '2000-01-02' from ai_grid_assessments
                         where run_id = :runId and policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL'
                        """, Map.of("runId", recurrenceRun), Boolean.class),
                        "replay must re-evaluate the stored run rather than return its prior row");
                assertEquals("NO_DECISION", jdbc.queryForObject("""
                        select decision from ai_grid_assessments
                         where run_id = :runId and policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL'
                        """, Map.of("runId", recurrenceRun), String.class));
                assertEquals("LOW_CONFIDENCE", jdbc.queryForObject("""
                        select evidence_readiness from ai_grid_assessments
                         where run_id = :runId and policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL'
                        """, Map.of("runId", recurrenceRun), String.class));
                assertEquals("OPEN", jdbc.queryForObject(
                        "select status from findings where id = :id", Map.of("id", findingId), String.class));
                return null;
            });
        } finally {
            jdbc.update("""
                    update platform.ai_grid_policy_versions
                       set required_facts_json = required_facts_json #- '{0,minConfidence}'
                     where policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL' and version = '2.0.0'
                    """, Map.of());
        }

        // Required controls are intentionally immutable for tenants.  Use an enabled
        // distribution in this isolated test to exercise the owner-facing closure path.
        jdbc.update("""
                update platform.ai_grid_policy_distribution
                   set default_selection = 'ENABLED', updated_at = now()
                 where policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL'
                """, Map.of());
        aiGridApiService.updateSelection(tenant, "AWS_BEDROCK_WEAK_GUARDRAIL", "DISABLED",
                "integration-reviewer", "Validate governance downgrade lifecycle");
        aiGridApiService.replay(tenant, recurrenceRun);
        tenantExecution.run(tenant, () -> {
            assertEquals("AUTO_CLOSED", jdbc.queryForObject(
                    "select status from findings where id = :id", Map.of("id", findingId), String.class));
            assertEquals("AUTO_POLICY_NOT_OWNER_FACING", jdbc.queryForObject(
                    "select closed_reason from findings where id = :id", Map.of("id", findingId), String.class));
            assertEquals(1, jdbc.queryForObject("""
                    select count(*) from finding_events
                     where finding_id = :id and event_type = 'AUTO_CLOSED'
                    """, Map.of("id", findingId), Integer.class));
            return null;
        });

        tenantExecution.run(tenant, () -> {
            assertThrows(DataIntegrityViolationException.class, () -> jdbc.update(
                    "update findings set finding_kind = 'VULNERABILITY' where id = :id",
                    Map.of("id", findingId)));
            return null;
        });
    }

    @Test
    void aiGridScopeFailureRollsBackAssessmentFindingAndOutboxAtomically() {
        Tenant tenant = provision("AI Grid Atomic Co", "ai-grid-atomic-co");
        UUID connectorId = connectorService.save(tenant,
                new AiSecurityAwsConnectorService.ConnectorConfigRequest(
                        "123456789012", null, null, List.of("us-east-1"), true)).id();
        UUID runId = syncRunFacade.start(tenant).getId();
        ArtifactObservation agent = new ArtifactObservation(
                "arn:aws:bedrock:us-east-1:123456789012:agent/atomic-agent",
                "AI_AGENT", "AWS_BEDROCK_AGENT", "Atomic agent",
                Map.of("guardrailAttached", true, "guardrailMinimumStrength", "LOW"));
        ArtifactObservation guardrail = new ArtifactObservation(
                "arn:aws:bedrock:us-east-1:123456789012:guardrail/atomic-guardrail",
                "GUARDRAIL", "AWS_BEDROCK_GUARDRAIL", "Atomic guardrail", Map.of());
        observationService.ingest(tenant, new ObservationEnvelopeV1(
                AiSecurityObservationService.CONTRACT_VERSION, runId, connectorId, tenant.getId(), "AWS",
                "123456789012", "us-east-1", "BEDROCK_AGENTS",
                "AWS:123456789012:us-east-1:BEDROCK_AGENTS", 0, 1,
                runId + ":atomic-agents:0", "atomic-agent-hash", Instant.now(), ScopeStatus.COMPLETE,
                List.of(agent, guardrail), List.of(new RelationshipObservation(
                        agent.providerResourceId(), guardrail.providerResourceId(), "USES_GUARDRAIL", Map.of())),
                List.of()));

        Map<String, Integer> baseline = tenantExecution.run(tenant, () -> Map.of(
                "assessments", count("ai_grid_assessments"),
                "outbox", count("ai_grid_outbox"),
                "findings", count("findings"),
                "receipts", count("ai_security_observation_receipts")));
        ObservationEnvelopeV1 completingScope = new ObservationEnvelopeV1(
                AiSecurityObservationService.CONTRACT_VERSION, runId, connectorId, tenant.getId(), "AWS",
                "123456789012", "us-east-1", "BEDROCK_GUARDRAILS",
                "AWS:123456789012:us-east-1:BEDROCK_GUARDRAILS", 0, 1,
                runId + ":atomic-guardrail:0", "atomic-guardrail-hash", Instant.now(), ScopeStatus.COMPLETE,
                List.of(guardrail), List.of(), List.of());

        doThrow(new IllegalStateException("injected reconciliation failure"))
                .when(reconciliationService).reconcile(eq(tenant), eq(runId), anyList());
        assertThrows(IllegalStateException.class, () -> observationService.ingest(tenant, completingScope));
        reset(reconciliationService);

        tenantExecution.run(tenant, () -> {
            assertEquals(baseline.get("assessments"), count("ai_grid_assessments"));
            assertEquals(baseline.get("outbox"), count("ai_grid_outbox"));
            assertEquals(baseline.get("findings"), count("findings"));
            assertEquals(baseline.get("receipts"), count("ai_security_observation_receipts"));
            return null;
        });

        observationService.ingest(tenant, completingScope);
        tenantExecution.run(tenant, () -> {
            assertEquals(1, jdbc.queryForObject(
                    "select count(*) from findings where finding_kind = 'AI_POSTURE'",
                    Map.of(), Integer.class));
            assertTrue(count("ai_grid_outbox") > baseline.get("outbox"));
            return null;
        });
    }

    @Test
    void azureRaiPolicySliceProducesFailPassAndNoDecisionWithoutOverclaiming() {
        Tenant tenant = provision("Azure RAI Answer Key", "azure-rai-answer-key");
        UUID connectorId = connectorService.save(
                tenant,
                new AiSecurityAwsConnectorService.ConnectorConfigRequest(
                        "123456789012", null, null, List.of("us-east-1"), true)
        ).id();

        UUID unsafeRun = syncRunFacade.start(tenant).getId();
        observationService.ingest(tenant, raiEnvelope(
                tenant, connectorId, unsafeRun, "rai-unsafe",
                Map.of("raiFilterEvidenceComplete", true, "raiNonBlockingFilterObserved", true)));
        tenantExecution.run(tenant, () -> {
            assertEquals("FAIL", raiDecision(unsafeRun));
            assertEquals(1, jdbc.queryForObject(
                    "select count(*) from findings where finding_kind = 'AI_POSTURE' and status = 'OPEN'",
                    Map.of(), Integer.class));
            return null;
        });

        UUID safeRun = syncRunFacade.start(tenant).getId();
        observationService.ingest(tenant, raiEnvelope(
                tenant, connectorId, safeRun, "rai-safe",
                Map.of("raiFilterEvidenceComplete", true, "raiNonBlockingFilterObserved", false)));
        tenantExecution.run(tenant, () -> {
            assertEquals("PASS", raiDecision(safeRun));
            assertEquals(0, jdbc.queryForObject(
                    "select count(*) from findings where finding_kind = 'AI_POSTURE' and status = 'OPEN'",
                    Map.of(), Integer.class));
            return null;
        });

        UUID incompleteRun = syncRunFacade.start(tenant).getId();
        observationService.ingest(tenant, raiEnvelope(
                tenant, connectorId, incompleteRun, "rai-incomplete",
                Map.of("raiFilterEvidenceComplete", false)));
        tenantExecution.run(tenant, () -> {
            assertEquals("NO_DECISION", raiDecision(incompleteRun));
            assertEquals("MISSING_FACTS", jdbc.queryForObject("""
                    select evidence_readiness from ai_grid_assessments
                     where run_id = :runId and policy_id = 'AZURE_RAI_POLICY_NON_BLOCKING_FILTER'
                    """, Map.of("runId", incompleteRun), String.class));
            return null;
        });
    }

    private ObservationEnvelopeV1 raiEnvelope(
            Tenant tenant, UUID connectorId, UUID runId, String hash, Map<String, Object> attributes
    ) {
        ArtifactObservation policy = new ArtifactObservation(
                "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/ai/raiPolicies/production",
                "AI_GUARDRAIL", "AZURE_RAI_POLICIES", "production", attributes);
        String scopeKey = "AWS:123456789012:us-east-1:AZURE_RAI_POLICIES";
        return new ObservationEnvelopeV1(
                AiSecurityObservationService.CONTRACT_VERSION, runId, connectorId, tenant.getId(), "AWS",
                "123456789012", "us-east-1", "AZURE_RAI_POLICIES", scopeKey, 0, 1,
                runId + ":rai:0", hash, Instant.now(), ScopeStatus.COMPLETE,
                List.of(policy), List.of(), List.of());
    }

    private String raiDecision(UUID runId) {
        return jdbc.queryForObject("""
                select decision from ai_grid_assessments
                 where run_id = :runId and policy_id = 'AZURE_RAI_POLICY_NON_BLOCKING_FILTER'
                """, Map.of("runId", runId), String.class);
    }

    private int count(String table) {
        return jdbc.queryForObject("select count(*) from " + table, Map.of(), Integer.class);
    }

    private UUID ingestR0Run(Tenant tenant, UUID connectorId, String strength, String suffix,
                             boolean completeGuardrailScope) {
        UUID runId = syncRunFacade.start(tenant).getId();
        ArtifactObservation agent = new ArtifactObservation(
                "arn:aws:bedrock:us-east-1:123456789012:agent/r0-agent",
                "AI_AGENT", "AWS_BEDROCK_AGENT", "R0 agent",
                Map.of("guardrailAttached", true, "guardrailMinimumStrength", strength,
                        "tags", Map.of("team", "AI Platform Team")));
        ArtifactObservation guardrail = new ArtifactObservation(
                "arn:aws:bedrock:us-east-1:123456789012:guardrail/r0-guardrail",
                "GUARDRAIL", "AWS_BEDROCK_GUARDRAIL", "R0 guardrail", Map.of());
        observationService.ingest(tenant, new ObservationEnvelopeV1(
                AiSecurityObservationService.CONTRACT_VERSION, runId, connectorId, tenant.getId(), "AWS",
                "123456789012", "us-east-1", "BEDROCK_AGENTS",
                "AWS:123456789012:us-east-1:BEDROCK_AGENTS", 0, 1,
                runId + ":agents:0", suffix + "-agent", Instant.now(), ScopeStatus.COMPLETE,
                List.of(agent, guardrail), List.of(new RelationshipObservation(
                        agent.providerResourceId(), guardrail.providerResourceId(), "USES_GUARDRAIL", Map.of())),
                List.of()));
        if (completeGuardrailScope) {
            observationService.ingest(tenant, new ObservationEnvelopeV1(
                    AiSecurityObservationService.CONTRACT_VERSION, runId, connectorId, tenant.getId(), "AWS",
                    "123456789012", "us-east-1", "BEDROCK_GUARDRAILS",
                    "AWS:123456789012:us-east-1:BEDROCK_GUARDRAILS", 0, 1,
                    runId + ":guardrails:0", suffix + "-guardrail", Instant.now(), ScopeStatus.COMPLETE,
                    List.of(guardrail), List.of(), List.of()));
        }
        return runId;
    }

    private Tenant provision(String name, String slug) {
        Tenant tenant = tenantService.createTenant(name, slug, "pilot", null);
        tenantSchemaMigrationService.provisionNewTenant(tenant);
        return tenant;
    }

    private int activeArtifacts(Tenant tenant) {
        return tenantExecution.run(tenant, () -> jdbc.queryForObject(
                "select count(*) from ai_security_artifacts where active = true",
                Map.of(),
                Integer.class));
    }

    private String wildcardRoleOutcome(Tenant tenant, UUID runId) {
        return tenantExecution.run(tenant, () -> jdbc.queryForObject("""
                select decision
                  from ai_grid_assessments
                 where run_id = :runId
                   and policy_id = 'AWS_BEDROCK_WILDCARD_AGENT_ROLE'
                """, Map.of("runId", runId), String.class));
    }

    private ObservationEnvelopeV1 evidenceEnvelope(
            Tenant tenant,
            UUID connectorId,
            UUID runId,
            String region,
            String resourceFamily,
            String hash,
            List<ArtifactObservation> artifacts
    ) {
        String scopeKey = "AWS:123456789012:" + region + ":" + resourceFamily;
        return new ObservationEnvelopeV1(
                AiSecurityObservationService.CONTRACT_VERSION,
                runId,
                connectorId,
                tenant.getId(),
                "AWS",
                "123456789012",
                region,
                resourceFamily,
                scopeKey,
                0,
                1,
                runId + ":" + scopeKey + ":0",
                hash,
                Instant.now(),
                ScopeStatus.COMPLETE,
                artifacts,
                List.of(),
                List.of());
    }

    private ObservationEnvelopeV1 envelope(
            Tenant tenant,
            UUID connectorId,
            UUID runId,
            String hash,
            ScopeStatus status,
            List<ArtifactObservation> artifacts
    ) {
        return new ObservationEnvelopeV1(
                AiSecurityObservationService.CONTRACT_VERSION,
                runId,
                connectorId,
                tenant.getId(),
                "AWS",
                "123456789012",
                "us-east-1",
                "BEDROCK_AGENTS",
                "AWS:123456789012:us-east-1:BEDROCK_AGENTS",
                0,
                1,
                runId + ":BEDROCK_AGENTS:0",
                hash,
                Instant.now(),
                status,
                artifacts,
                List.of(),
                List.of());
    }
}
