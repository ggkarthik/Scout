package com.prototype.vulnwatch.aisecurity.copilot;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.azure.core.credential.TokenCredential;
import com.prototype.vulnwatch.aisecurity.azure.AiSecurityAzureCredentialService;
import com.prototype.vulnwatch.aisecurity.azure.AiSecurityAzureCredentialService.CredentialSecret;
import com.prototype.vulnwatch.aisecurity.copilot.CopilotStudioDataverseClient.Bot;
import com.prototype.vulnwatch.aisecurity.copilot.CopilotStudioDataverseClient.Component;
import com.prototype.vulnwatch.aisecurity.copilot.CopilotStudioDataverseClient.ComponentCategory;
import com.prototype.vulnwatch.aisecurity.copilot.CopilotStudioDataverseClient.Discovery;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ObservationEnvelopeV1;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ScopeStatus;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityConnectorFeatureFlagService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityObservationService;
import com.prototype.vulnwatch.aisecurity.service.AiGridCapabilityService;
import com.prototype.vulnwatch.aisecurity.service.AiGridBudgetService;
import com.prototype.vulnwatch.aisecurity.service.AiGridProviderCallCounter;
import com.prototype.vulnwatch.aisecurity.service.AiGridRunMetricsService;
import com.prototype.vulnwatch.aisecurity.service.AiSecuritySyncRunFacade;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.domain.Tenant;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class CopilotStudioDiscoveryServiceTest {

    @Test
    void createsInventoryObservationAndCompletesThePolicyEligibleRun() {
        CopilotStudioConnectorService configs = mock(CopilotStudioConnectorService.class);
        AiSecurityAzureCredentialService credentials = mock(AiSecurityAzureCredentialService.class);
        CopilotStudioDataverseClient dataverse = mock(CopilotStudioDataverseClient.class);
        AiSecurityObservationService observations = mock(AiSecurityObservationService.class);
        AiSecuritySyncRunFacade runs = mock(AiSecuritySyncRunFacade.class);
        AiGridCapabilityService capabilities = mock(AiGridCapabilityService.class);
        AiGridBudgetService budgets = mock(AiGridBudgetService.class);
        AiGridProviderCallCounter providerCalls = new AiGridProviderCallCounter();
        AiGridRunMetricsService runMetrics = mock(AiGridRunMetricsService.class);
        AiSecurityConnectorFeatureFlagService featureFlags = mock(AiSecurityConnectorFeatureFlagService.class);
        CopilotStudioDiscoveryService service = new CopilotStudioDiscoveryService(
                configs, credentials, dataverse, observations, runs, capabilities, budgets, providerCalls, runMetrics,
                featureFlags, true, 100);

        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        UUID connectorId = UUID.randomUUID();
        UUID profileId = UUID.randomUUID();
        UUID runId = UUID.randomUUID();
        String organization = "https://org.crm.dynamics.com";
        when(configs.required(tenant, connectorId)).thenReturn(new CopilotStudioConnectorService.Response(
                connectorId, organization, profileId, true, false, false, "0 0 * * * *",
                List.of("org.crm.dynamics.com"), Instant.now(), Instant.now()));
        CredentialSecret secret = new CredentialSecret(
                profileId, "CLIENT_SECRET", "tenant-id", "client-id", "secret",
                Instant.now().plusSeconds(3600), "ACTIVE");
        TokenCredential tokenCredential = mock(TokenCredential.class);
        when(credentials.secret(tenant, profileId)).thenReturn(secret);
        when(credentials.tokenCredential(secret)).thenReturn(tokenCredential);
        when(dataverse.discover(tenant, tokenCredential, organization)).thenReturn(new Discovery(
                List.of(new Bot("bot-1", "Support bot", "PUBLISHED", "3")),
                List.of(new Component("prompt-1", "Greeting", "TOPIC", "1", "bot-1", true,
                        ComponentCategory.PROMPT, null)),
                List.of()));
        SyncRun run = mock(SyncRun.class);
        when(run.getId()).thenReturn(runId);
        when(runs.start(tenant, AiSecuritySyncRunFacade.COPILOT_SYNC_TYPE)).thenReturn(run);
        CopilotStudioDiscoveryService.Result result = service.run(tenant, connectorId);

        ArgumentCaptor<ObservationEnvelopeV1> envelope = ArgumentCaptor.forClass(ObservationEnvelopeV1.class);
        verify(observations).ingest(eq(tenant), envelope.capture());
        assertEquals("MICROSOFT_COPILOT", envelope.getValue().provider());
        assertEquals(ScopeStatus.COMPLETE, envelope.getValue().completionStatus());
        assertEquals(3, envelope.getValue().artifacts().size());
        assertTrue(envelope.getValue().relationships().stream()
                .anyMatch(relationship -> "USES_PROMPT".equals(relationship.relationshipType())));
        assertEquals(3, result.artifacts());
        verify(runs).complete(tenant.getId(), runId, 3, 0, null);
        verify(budgets).admit(tenant, runId, "MICROSOFT_COPILOT", List.of("COPILOT_STUDIO"), "*", "*");
        verify(budgets).reconcile(tenant, runId, "MICROSOFT_COPILOT");
        verify(featureFlags).assertEnabled(
                tenant, AiSecurityConnectorFeatureFlagService.Feature.COPILOT_DISCOVERY, true);
    }
}
