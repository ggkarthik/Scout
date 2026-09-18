package com.prototype.vulnwatch.aisecurity.azure;

import com.prototype.vulnwatch.aisecurity.service.AiAgentExecutionIngestionService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityConnectorFeatureFlagService;
import com.prototype.vulnwatch.domain.Tenant;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/** Cursor-window Foundry runtime poller; inventory remains independent of runtime failures. */
@Service
public class AzureFoundryRuntimeCollectionService {
    private final AiSecurityAzureFoundryConfigService config; private final AiSecurityAzureConnectorService connectors;
    private final AiSecurityAzureCredentialService credentials; private final AzureFoundryRuntimeMetadataClient client;
    private final AiAgentExecutionIngestionService ingestion;
    private final AiSecurityConnectorFeatureFlagService featureFlags;
    private final boolean enabled;
    public AzureFoundryRuntimeCollectionService(AiSecurityAzureFoundryConfigService config, AiSecurityAzureConnectorService connectors, AiSecurityAzureCredentialService credentials, AzureFoundryRuntimeMetadataClient client, AiAgentExecutionIngestionService ingestion, AiSecurityConnectorFeatureFlagService featureFlags,
                                                @Value("${app.ai-security.runtime.enabled:false}") boolean enabled) {
        this.config=config; this.connectors=connectors; this.credentials=credentials; this.client=client; this.ingestion=ingestion;
        this.featureFlags=featureFlags; this.enabled = enabled;
    }
    public Result run(Tenant tenant) {
        featureFlags.assertEnabled(tenant, AiSecurityConnectorFeatureFlagService.Feature.AZURE_FOUNDRY_RUNTIME, enabled);
        var setup = config.get(tenant); if (!setup.configured() || setup.connectorId() == null || setup.foundryEndpointUrl() == null) throw new IllegalStateException("Foundry runtime is not configured");
        var cursor = ingestion.cursor(
                tenant, setup.connectorId(), "AZURE_FOUNDRY_RUNTIME", setup.foundryEndpointUrl());
        Instant after = (cursor.timestamp() == null ? Instant.now().minus(cursor.lookbackDays(), ChronoUnit.DAYS)
                : cursor.timestamp().minus(cursor.overlapDays(), ChronoUnit.DAYS));
        var connector = connectors.secret(tenant, setup.connectorId()); var profile = credentials.secret(tenant, connector.credentialProfileId());
        int accepted=0, duplicates=0;
        var collection = client.list(credentials.tokenCredential(profile), setup.foundryEndpointUrl(), after);
        for (var run : collection.executions()) {
            var resolution = ingestion.resolveAgent(tenant, "AZURE", run.agentReference(), run.agentVersionReference());
            var result = ingestion.ingest(tenant, connector.id(), new AiAgentExecutionIngestionService.RuntimeExecution("AZURE_FOUNDRY", run.id(), resolution.agentArtifactId(), "AZURE_FOUNDRY_RUNTIME", setup.foundryEndpointUrl(), run.startedAt(), run.completedAt(), run.status() == null ? "UNKNOWN" : run.status(), run.outcomeCategory(), run.approvalState(), run.policyState(), run.classification(), "v1", run.tokenCount(), run.latencyMs(), null, null, run.completedAt() == null ? (run.startedAt() == null ? Instant.now() : run.startedAt()) : run.completedAt(), java.util.List.of(), resolution.agentVersionArtifactId(), run.agentReference(), run.agentVersionReference(), resolution.status(), resolution.diagnostic()));
            if (result.duplicate()) duplicates++; else accepted++;
        }
        return new Result(accepted, duplicates, after, collection.status(), collection.diagnostic());
    }
    public record Result(int accepted, int duplicates, Instant windowStart, String coverageStatus, String diagnostic) { }
}
