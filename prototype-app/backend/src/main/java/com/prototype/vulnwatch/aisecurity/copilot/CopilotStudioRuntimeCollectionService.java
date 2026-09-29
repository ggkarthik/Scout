package com.prototype.vulnwatch.aisecurity.copilot;

import com.prototype.vulnwatch.aisecurity.azure.AiSecurityAzureCredentialService;
import com.prototype.vulnwatch.aisecurity.service.AiAgentExecutionIngestionService;
import com.prototype.vulnwatch.aisecurity.service.AiGridCapabilityService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityConnectorFeatureFlagService;
import com.prototype.vulnwatch.domain.Tenant;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class CopilotStudioRuntimeCollectionService {
    private final CopilotStudioConnectorService configs; private final AiSecurityAzureCredentialService credentials;
    private final CopilotStudioDataverseClient dataverse; private final AiAgentExecutionIngestionService ingestion;
    private final boolean runtimeEnabled; private final boolean copilotEnabled;
    private final AiSecurityConnectorFeatureFlagService featureFlags;
    private final AiGridCapabilityService capabilities;
    public CopilotStudioRuntimeCollectionService(CopilotStudioConnectorService configs, AiSecurityAzureCredentialService credentials, CopilotStudioDataverseClient dataverse, AiAgentExecutionIngestionService ingestion, AiSecurityConnectorFeatureFlagService featureFlags, AiGridCapabilityService capabilities,
                                                 @Value("${app.ai-security.runtime.enabled:false}") boolean runtimeEnabled,
                                                 @Value("${app.ai-security.copilot.enabled:false}") boolean copilotEnabled) { this.configs=configs; this.credentials=credentials; this.dataverse=dataverse; this.ingestion=ingestion; this.featureFlags=featureFlags; this.capabilities=capabilities; this.runtimeEnabled=runtimeEnabled; this.copilotEnabled=copilotEnabled; }
    public Result run(Tenant tenant, UUID connectorId) {
        featureFlags.assertEnabled(tenant, AiSecurityConnectorFeatureFlagService.Feature.COPILOT_RUNTIME,
                runtimeEnabled && copilotEnabled);
        var config=configs.required(tenant, connectorId); if (!config.executionEnabled() || config.killSwitch()) throw new IllegalStateException("Copilot runtime collection is disabled");
        var cursor=ingestion.cursor(tenant, connectorId, "COPILOT_STUDIO_RUNTIME", config.organizationUrl());
        Instant after=cursor.timestamp() == null ? Instant.now().minus(cursor.lookbackDays(), ChronoUnit.DAYS)
                : cursor.timestamp().minus(cursor.overlapDays(), ChronoUnit.DAYS);
        var profile=credentials.secret(tenant, config.credentialProfileId()); int accepted=0, duplicates=0;
        var executions = dataverse.executions(credentials.tokenCredential(profile), config.organizationUrl(), after);
        for (var execution: executions) {
            Instant time=execution.occurredAt()==null?Instant.now():execution.occurredAt();
            UUID agentId = execution.botId() == null ? null : ingestion.artifactId(
                    tenant, config.organizationUrl() + "/bots/" + execution.botId());
            var resolution = agentId == null
                    ? new AiAgentExecutionIngestionService.AgentResolution(null, null, "UNRESOLVED", "AGENT_REFERENCE_NOT_FOUND")
                    : ingestion.resolveAgent(tenant, "MICROSOFT_COPILOT", config.organizationUrl() + "/bots/" + execution.botId(), null);
            var result=ingestion.ingest(tenant,connectorId,new AiAgentExecutionIngestionService.RuntimeExecution("MICROSOFT_COPILOT",execution.id(),resolution.agentArtifactId(),"COPILOT_STUDIO_RUNTIME",config.organizationUrl(),time,time,execution.status()==null?"UNKNOWN":execution.status(),null,null,null,null,"Dataverse v9.2",null,null,null,null,time,List.of(),resolution.agentVersionArtifactId(),execution.botId(),null,resolution.status(),resolution.diagnostic()));
            if(result.duplicate()) duplicates++; else accepted++;
        }
        capabilities.recordRuntimeCapabilities(tenant, "MICROSOFT_COPILOT", "COPILOT_STUDIO_RUNTIME",
                connectorId.toString(), "GLOBAL", "COMPLETE", "Dataverse execution metadata collected",
                List.of("RUNTIME_EXECUTION_METADATA"));
        capabilities.recordRuntimeCapabilities(tenant, "MICROSOFT_COPILOT", "COPILOT_STUDIO_RUNTIME",
                connectorId.toString(), "GLOBAL", "PARTIAL", "Bot version correlation is unavailable",
                List.of("RUNTIME_VERSION_CORRELATION"));
        capabilities.recordRuntimeCapabilities(tenant, "MICROSOFT_COPILOT", "COPILOT_STUDIO_RUNTIME",
                connectorId.toString(), "GLOBAL", "UNSUPPORTED_API",
                "Dataverse transcript metadata does not expose qualified action decisions",
                List.of("RUNTIME_EVENT_DECISIONS", "RUNTIME_ACTION_OUTCOMES",
                        "RUNTIME_TOOL_CORRELATION", "RUNTIME_DATA_CLASSIFICATION"));
        return new Result(accepted,duplicates,after);
    }
    public record Result(int accepted,int duplicates,Instant windowStart) { }
}
