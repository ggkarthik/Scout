package com.prototype.vulnwatch.aisecurity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ArtifactObservation;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ObservationEnvelopeV1;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ScopeStatus;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAwsConnectorService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityObservationService;
import com.prototype.vulnwatch.aisecurity.service.AiSecuritySyncRunFacade;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.FindingDeltaQueueService;
import com.prototype.vulnwatch.service.IngestionJobWorkerService;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
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
    @Autowired private AiSecuritySyncRunFacade syncRunFacade;
    @Autowired private NamedParameterJdbcTemplate jdbc;

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
                        "BEDROCK_AGENT",
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
                "BEDROCK_AGENT",
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
                select outcome
                  from ai_security_policy_evaluations
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
