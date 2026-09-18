package com.prototype.vulnwatch.aisecurity.copilot;

import com.prototype.vulnwatch.aisecurity.azure.AiSecurityAzureCredentialService;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ArtifactObservation;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.Diagnostic;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ObservationEnvelopeV1;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.RelationshipObservation;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ScopeStatus;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityObservationService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityConnectorFeatureFlagService;
import com.prototype.vulnwatch.aisecurity.service.AiSecuritySyncRunFacade;
import com.prototype.vulnwatch.domain.Tenant;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/** Maps Dataverse metadata into the standard whole-sweep observation contract. */
@Service
public class CopilotStudioDiscoveryService {
    private final CopilotStudioConnectorService configs; private final AiSecurityAzureCredentialService credentials;
    private final CopilotStudioDataverseClient dataverse; private final AiSecurityObservationService observations;
    private final AiSecuritySyncRunFacade runs;
    private final AiSecurityConnectorFeatureFlagService featureFlags;
    private final boolean enabled;
    public CopilotStudioDiscoveryService(CopilotStudioConnectorService configs, AiSecurityAzureCredentialService credentials,
                                         CopilotStudioDataverseClient dataverse, AiSecurityObservationService observations,
                                         AiSecuritySyncRunFacade runs, AiSecurityConnectorFeatureFlagService featureFlags,
                                         @Value("${app.ai-security.copilot.enabled:false}") boolean enabled) {
        this.configs = configs; this.credentials = credentials; this.dataverse = dataverse; this.observations = observations;
        this.runs = runs;
        this.featureFlags = featureFlags;
        this.enabled = enabled;
    }
    public Result run(Tenant tenant, UUID connectorId) {
        featureFlags.assertEnabled(tenant, AiSecurityConnectorFeatureFlagService.Feature.COPILOT_DISCOVERY, enabled);
        var config = configs.required(tenant, connectorId);
        if (!config.discoveryEnabled() || config.killSwitch()) throw new ResponseStatusException(HttpStatus.CONFLICT, "Copilot discovery is disabled");
        UUID runId = runs.start(tenant, AiSecuritySyncRunFacade.COPILOT_SYNC_TYPE).getId();
        try {
            Result result = collect(tenant, connectorId, config, runId);
            runs.complete(tenant.getId(), runId, result.artifacts(), result.incompleteScopes(), null);
            return result;
        } catch (RuntimeException error) {
            runs.fail(tenant.getId(), runId, "Copilot Studio discovery failed: " + error.getClass().getSimpleName());
            throw error;
        }
    }
    private Result collect(Tenant tenant, UUID connectorId, CopilotStudioConnectorService.Response config, UUID runId) {
        var profile = credentials.secret(tenant, config.credentialProfileId());
        var source = dataverse.discover(tenant, credentials.tokenCredential(profile), config.organizationUrl());
        List<ArtifactObservation> artifacts = new ArrayList<>(); List<RelationshipObservation> relationships = new ArrayList<>();
        Map<String, String> versionByBot = new HashMap<>();
        for (var bot : source.bots()) {
            String botId = id(config.organizationUrl(), "bots", bot.id()); String version = bot.version() == null ? "published" : bot.version();
            String versionId = id(config.organizationUrl(), "bots", bot.id(), "versions", version);
            versionByBot.put(bot.id(), versionId);
            artifacts.add(new ArtifactObservation(botId, "AI_AGENT", "MICROSOFT_COPILOT", safeName(bot.name(), "Copilot"), Map.of("sourceType", "COPILOT_STUDIO", "status", safe(bot.state()))));
            artifacts.add(new ArtifactObservation(versionId, "AI_AGENT_VERSION", "MICROSOFT_COPILOT_VERSION", safeName(bot.name(), "Copilot") + " v" + version, Map.of("sourceType", "COPILOT_STUDIO", "version", version)));
            relationships.add(edge(versionId, botId, "VERSION_OF")); relationships.add(edge(botId, versionId, "ACTIVE_VERSION"));
        }
        for (var component : source.components()) {
            String componentId = id(config.organizationUrl(), "components", component.id());
            String artifactType = switch (component.category()) {
                case PROMPT -> "AI_PROMPT";
                case TOOL -> "AI_TOOL";
                case COMPONENT -> "AI_COMPONENT";
            };
            String nativeKind = switch (component.category()) {
                case PROMPT -> "MICROSOFT_COPILOT_PROMPT";
                case TOOL -> "MICROSOFT_COPILOT_TOOL";
                case COMPONENT -> "MICROSOFT_COPILOT_COMPONENT";
            };
            Map<String, Object> attributes = new java.util.LinkedHashMap<>();
            attributes.put("sourceType", "COPILOT_STUDIO");
            attributes.put("componentType", safe(component.kind()));
            attributes.put("version", safe(component.version()));
            if (component.digest() != null) {
                attributes.put(component.category() == CopilotStudioDataverseClient.ComponentCategory.TOOL
                        ? "toolDefinitionDigest" : "promptDigest", component.digest().value());
                attributes.put("digestAlgorithm", component.digest().algorithm());
                attributes.put("digestKeyVersion", component.digest().keyVersion());
            }
            artifacts.add(new ArtifactObservation(componentId, artifactType, nativeKind,
                    safeName(component.name(), "Copilot component"), attributes));
            String versionId = versionByBot.get(component.botId());
            if (versionId != null) {
                String relationship = switch (component.category()) {
                    case PROMPT -> "USES_PROMPT";
                    case TOOL -> "USES_TOOL";
                    case COMPONENT -> "HAS_COMPONENT";
                };
                relationships.add(edge(versionId, componentId, relationship));
                if (component.category() == CopilotStudioDataverseClient.ComponentCategory.TOOL) {
                    String botId = id(config.organizationUrl(), "bots", component.botId());
                    relationships.add(edge(botId, componentId, "USES_TOOL"));
                }
            }
        }
        List<Diagnostic> diagnostics = source.coverageGaps().stream().map(gap -> new Diagnostic(
                "COPILOT_" + gap.scope(), "Copilot scope is incomplete",
                gap.status() == 429 || gap.status() >= 500, List.of(), null)).toList();
        ScopeStatus status = diagnostics.isEmpty() ? ScopeStatus.COMPLETE : ScopeStatus.PARTIAL;
        observations.ingest(tenant, new ObservationEnvelopeV1("OBSERVATION_V1", runId, connectorId, tenant.getId(), "MICROSOFT_COPILOT", null,
                config.organizationUrl(), "GLOBAL", "COPILOT_STUDIO", config.organizationUrl(), 1, 1, hash(runId + "|" + artifacts.size()), hash("copilot|" + artifacts.size() + "|" + relationships.size()), Instant.now(), status, artifacts, relationships, diagnostics));
        return new Result(runId, artifacts.size(), diagnostics.size(), status);
    }
    public CopilotStudioDataverseClient.PermissionTest test(Tenant tenant, UUID connectorId) {
        var config = configs.required(tenant, connectorId);
        var profile = credentials.secret(tenant, config.credentialProfileId());
        return dataverse.testPermissions(credentials.tokenCredential(profile), config.organizationUrl());
    }
    private static RelationshipObservation edge(String source, String target, String type) { return new RelationshipObservation(source, target, type, Map.of("confidence", "DIRECT", "evidence", Map.of("sourceApi", "Dataverse", "field", "metadata"))); }
    private static String id(String root, String... parts) { return root + "/" + String.join("/", parts); }
    private static String safe(String value) { return value == null ? "UNKNOWN" : value; }
    private static String safeName(String value, String fallback) { return value == null || value.isBlank() ? fallback : value; }
    private static String hash(String value) { try { return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); } catch (Exception e) { throw new IllegalStateException(e); } }
    public record Result(UUID runId, int artifacts, int incompleteScopes, ScopeStatus status) { }
}
