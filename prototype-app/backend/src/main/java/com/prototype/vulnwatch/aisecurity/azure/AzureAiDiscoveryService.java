package com.prototype.vulnwatch.aisecurity.azure;

import com.azure.core.credential.TokenCredential;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.aisecurity.azure.AiSecurityAzureConnectorService.ConnectorSecret;
import com.prototype.vulnwatch.aisecurity.azure.AzureAiManagementClient.AzureApiFailure;
import com.prototype.vulnwatch.aisecurity.azure.AzureAiManagementClient.AzureApiException;
import com.prototype.vulnwatch.aisecurity.azure.AzureAiManagementClient.AzureResource;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ArtifactObservation;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.Diagnostic;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ObservationEnvelopeV1;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.RelationshipObservation;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ScopeStatus;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityDiscoveryProvider;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityObservationService;
import com.prototype.vulnwatch.aisecurity.service.AiSecuritySyncRunFacade;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.IngestionJobService;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class AzureAiDiscoveryService implements AiSecurityDiscoveryProvider {

    private static final Set<String> SEARCH_DATA_FAMILIES = Set.of(
            "AZURE_SEARCH_INDEXES",
            "AZURE_SEARCH_SKILLSETS",
            "AZURE_SEARCH_INDEXERS",
            "AZURE_SEARCH_DATA_SOURCES");

    private final AiSecurityAzureConnectorService connectors;
    private final AiSecurityAzureCredentialService credentials;
    private final AzureAiManagementClient azure;
    private final AiSecurityAzureAdmissionService admission;
    private final AiSecurityObservationService observations;
    private final AiSecuritySyncRunFacade runs;
    private final AzurePolicyPermissionMatrix permissionMatrix;
    private final AiSecurityAzureKillSwitchService killSwitches;
    private final AiSecurityAzureMetrics metrics;
    private final ObjectMapper objectMapper;
    private final boolean enabled;
    private final boolean foundryAgentsEnabled;
    private final boolean searchDataPlaneEnabled;

    public AzureAiDiscoveryService(
            AiSecurityAzureConnectorService connectors,
            AiSecurityAzureCredentialService credentials,
            AzureAiManagementClient azure,
            AiSecurityAzureAdmissionService admission,
            AiSecurityObservationService observations,
            AiSecuritySyncRunFacade runs,
            AzurePolicyPermissionMatrix permissionMatrix,
            AiSecurityAzureKillSwitchService killSwitches,
            AiSecurityAzureMetrics metrics,
            ObjectMapper objectMapper,
            @Value("${app.ai-security.azure.enabled:false}") boolean enabled,
            @Value("${app.ai-security.azure.foundry-agents.enabled:false}") boolean foundryAgentsEnabled,
            @Value("${app.ai-security.azure.search-data-plane.enabled:false}") boolean searchDataPlaneEnabled
    ) {
        this.connectors = connectors;
        this.credentials = credentials;
        this.azure = azure;
        this.admission = admission;
        this.observations = observations;
        this.runs = runs;
        this.permissionMatrix = permissionMatrix;
        this.killSwitches = killSwitches;
        this.metrics = metrics;
        this.objectMapper = objectMapper;
        this.enabled = enabled;
        this.foundryAgentsEnabled = foundryAgentsEnabled;
        this.searchDataPlaneEnabled = searchDataPlaneEnabled;
    }

    @Override
    public String provider() {
        return "AZURE";
    }

    @Override
    public String jobType() {
        return IngestionJobService.JOB_TYPE_AI_SECURITY_AZURE_DISCOVERY;
    }

    @Override
    public Object discover(Tenant tenant, UUID connectorId) {
        if (!enabled) {
            metrics.recordRun("disabled");
            throw new IllegalStateException("Azure AI Security discovery is disabled");
        }
        try {
            killSwitches.assertDiscoveryAllowed(tenant.getId(), connectorId);
        } catch (AiSecurityAzureKillSwitchService.DiscoveryDisabledException exception) {
            metrics.recordRun("disabled");
            throw exception;
        }
        ConnectorSecret connector = connectors.secret(tenant, connectorId);
        var profile = credentials.secret(tenant, connector.credentialProfileId());
        if (!profile.azureTenantId().equalsIgnoreCase(connector.azureTenantId())) {
            throw new IllegalArgumentException("Azure credential tenant does not match connector tenant");
        }

        SyncRun run = runs.start(tenant, AiSecuritySyncRunFacade.AZURE_SYNC_TYPE);
        Instant startedAt = Instant.now();
        int observed = 0;
        int incomplete = 0;
        try (var permit = admission.acquire(connector.subscriptionId())) {
            TokenCredential credential = credentials.tokenCredential(profile);
            var snapshot = azure.discover(
                    credential,
                    connector.subscriptionId(),
                    Set.copyOf(connector.resourceFamilies()),
                    foundryAgentsEnabled);
            Map<String, AzureResource> allResources = index(snapshot.resources());
            for (String family : connector.resourceFamilies()) {
                for (ScopePayload payload : payloads(family, connector, snapshot, allResources)) {
                    observations.ingest(tenant, envelope(tenant, connector, run.getId(), payload));
                    metrics.recordScope(payload.family(), payload.status().name());
                    observed += payload.artifacts().size();
                    if (payload.status() != ScopeStatus.COMPLETE) {
                        incomplete++;
                    }
                }
            }
            runs.complete(tenant.getId(), run.getId(), observed, incomplete, json(Map.of(
                    "provider", "AZURE",
                    "connectorId", connector.id(),
                    "subscriptionId", connector.subscriptionId(),
                    "families", connector.resourceFamilies())));
            metrics.recordRun("completed");
            return new DiscoveryResult(run.getId(), observed, incomplete);
        } catch (Exception exception) {
            runs.fail(tenant.getId(), run.getId(), "Azure AI Security discovery failed");
            metrics.recordRun("failed");
            throw exception;
        } finally {
            metrics.recordRunDuration(Duration.between(startedAt, Instant.now()));
        }
    }

    private List<ScopePayload> payloads(
            String family,
            ConnectorSecret connector,
            AzureAiManagementClient.DiscoverySnapshot snapshot,
            Map<String, AzureResource> allResources
    ) {
        List<String> regions = scopeRegions(family, connector, snapshot.resources().getOrDefault(family, List.of()));
        if (regions.isEmpty()) {
            return List.of(new ScopePayload(
                    family,
                    "GLOBAL",
                    ScopeStatus.PARTIAL,
                    List.of(),
                    List.of(),
                    List.of(diagnostic(
                            "INVALID_CONFIGURATION",
                            "At least one Azure region is required for regional discovery",
                            false,
                            family))));
        }
        List<ScopePayload> payloads = new ArrayList<>();
        for (String region : regions) {
            payloads.add(payload(family, region, snapshot, allResources));
        }
        return payloads;
    }

    private ScopePayload payload(
            String family,
            String region,
            AzureAiManagementClient.DiscoverySnapshot snapshot,
            Map<String, AzureResource> allResources
    ) {
        if (killSwitches.isResourceFamilyDisabled(family)) {
            return unsupported(family, region, "DISABLED_BY_KILL_SWITCH",
                    "Azure AI Security discovery is disabled for this resource family");
        }
        if (("AZURE_FOUNDRY_AGENTS".equals(family) || "AZURE_FOUNDRY_AGENT_TOOLS".equals(family))
                && !foundryAgentsEnabled) {
            return unsupported(family, region, "UNSUPPORTED_API_VERSION",
                    "Foundry agent preview discovery is disabled");
        }
        if (SEARCH_DATA_FAMILIES.contains(family)) {
            String message = searchDataPlaneEnabled
                    ? "Azure AI Search data-plane adapter is awaiting least-privilege certification"
                    : "Azure AI Search data-plane discovery is not certified";
            return unsupported(family, region, "UNSUPPORTED_API_VERSION", message);
        }
        AzureApiFailure failure = snapshot.failures().get(family);
        List<AzureResource> familyResources = "AZURE_FOUNDRY_AGENT_TOOLS".equals(family)
                ? agentTools(snapshot.resources().getOrDefault("AZURE_FOUNDRY_AGENTS", List.of()))
                : snapshot.resources().getOrDefault(family, List.of());
        List<AzureResource> resources = familyResources.stream()
                .filter(resource -> isGlobalFamily(family) || region.equalsIgnoreCase(resource.location()))
                .toList();
        List<ArtifactObservation> artifacts = new ArrayList<>();
        List<RelationshipObservation> relationships = new ArrayList<>();
        Set<String> included = new LinkedHashSet<>();
        for (AzureResource resource : resources) {
            addArtifact(artifacts, included, resource, family, snapshot);
            if (resource.parentId() != null) {
                AzureResource parent = allResources.get(resource.parentId().toLowerCase(Locale.ROOT));
                if (parent != null) {
                    addArtifact(artifacts, included, parent, resourceFamily(parent.type()), snapshot);
                    relationships.add(new RelationshipObservation(
                            parent.id(),
                            resource.id(),
                            relationship(family),
                            Map.of("provider", "AZURE")));
                }
            }
        }

        if ("AZURE_BOT_IDENTITIES".equals(family)) {
            for (AzureResource bot : snapshot.resources().getOrDefault("AZURE_BOT_SERVICES", List.of())) {
                String principalId = text(bot.identity().path("principalId"));
                if (principalId != null) {
                    AzureResource identity = syntheticIdentity(bot, principalId);
                    addArtifact(artifacts, included, bot, "AZURE_BOT_SERVICES", snapshot);
                    addArtifact(artifacts, included, identity, family, snapshot);
                    relationships.add(new RelationshipObservation(
                            bot.id(), identity.id(), "USES_MANAGED_IDENTITY", Map.of()));
                }
            }
        }
        if ("AZURE_RBAC_GLOBAL".equals(family)) {
            for (AzureResource assignment : resources) {
                String principalId = text(assignment.properties().path("principalId"));
                if (principalId == null) continue;
                AzureResource identity = syntheticPrincipal(assignment, principalId);
                addArtifact(artifacts, included, identity, "AZURE_IDENTITY", snapshot);
                relationships.add(new RelationshipObservation(
                        identity.id(), assignment.id(), "HAS_ROLE_ASSIGNMENT", Map.of()));
            }
        }

        if (failure == null) {
            return new ScopePayload(family, region, ScopeStatus.COMPLETE, artifacts, relationships, List.of());
        }
        ScopeStatus status = "UNSUPPORTED_API_VERSION".equals(failure.code())
                ? ScopeStatus.UNSUPPORTED
                : failure.retryable() ? ScopeStatus.FAILED : ScopeStatus.PARTIAL;
        return new ScopePayload(family, region, status, artifacts, relationships, List.of(
                diagnostic(failure.code(), failure.message(), failure.retryable(), family)));
    }

    private void addArtifact(
            List<ArtifactObservation> artifacts,
            Set<String> included,
            AzureResource resource,
            String family,
            AzureAiManagementClient.DiscoverySnapshot snapshot
    ) {
        if (resource == null || resource.id() == null || !included.add(resource.id())) {
            return;
        }
        artifacts.add(new ArtifactObservation(
                resource.id(),
                artifactType(family),
                nativeKind(family),
                resource.name() == null ? resource.id() : resource.name(),
                attributes(resource, family, snapshot)));
    }

    private Map<String, Object> attributes(
            AzureResource resource,
            String family,
            AzureAiManagementClient.DiscoverySnapshot snapshot
    ) {
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("originalArmId", nullToEmpty(resource.originalId()));
        values.put("resourceGroup", nullToEmpty(resource.resourceGroup()));
        values.put("azureResourceType", nullToEmpty(resource.type()));
        values.put("kind", nullToEmpty(resource.kind()));
        values.put("location", nullToEmpty(resource.location()));
        values.put("tags", resource.tags());
        values.put("provisioningState", nullToEmpty(text(resource.properties().path("provisioningState"))));
        values.put("identityType", nullToEmpty(text(resource.identity().path("type"))));

        if ("AZURE_AI_ACCOUNTS".equals(family) || "AZURE_SEARCH_SERVICES".equals(family)
                || "AZURE_ML_WORKSPACES".equals(family)) {
            String publicAccess = text(resource.properties().path("publicNetworkAccess"));
            String defaultAction = text(resource.properties().path("networkAcls").path("defaultAction"));
            int privateEndpoints = size(resource.properties().path("privateEndpointConnections"));
            boolean unrestricted = "Enabled".equalsIgnoreCase(publicAccess)
                    && (defaultAction == null || "Allow".equalsIgnoreCase(defaultAction))
                    && privateEndpoints == 0;
            values.put("publicNetworkAccess", nullToEmpty(publicAccess));
            values.put("networkDefaultAction", nullToEmpty(defaultAction));
            values.put("privateEndpointCount", privateEndpoints);
            values.put("publicNetworkUnrestricted", unrestricted);
        }
        if ("AZURE_AI_ACCOUNTS".equals(family)) {
            boolean disableLocalAuth = resource.properties().path("disableLocalAuth").asBoolean(false);
            values.put("disableLocalAuth", disableLocalAuth);
            values.put("localAuthEnabled", !disableLocalAuth);
            values.put("customerManagedKey", "Microsoft.KeyVault".equalsIgnoreCase(
                    text(resource.properties().path("encryption").path("keySource"))));
            values.put("diagnosticLoggingEnabled", diagnosticLoggingEnabled(resource.id(), snapshot));
        }
        if ("AZURE_FOUNDRY_DEPLOYMENTS".equals(family)) {
            values.put("modelName", nullToEmpty(text(resource.properties().path("model").path("name"))));
            values.put("modelVersion", nullToEmpty(text(resource.properties().path("model").path("version"))));
            values.put("scaleType", nullToEmpty(text(resource.properties().path("scaleSettings").path("scaleType"))));
            values.put("capacity", resource.sku().path("capacity").asInt(0));
        }
        if ("AZURE_FOUNDRY_AGENTS".equals(family)) {
            values.put("modelDeployment", nullToEmpty(text(resource.properties().path("modelDeploymentName"))));
            values.put("codeInterpreterEnabled", hasTool(resource.properties(), "code_interpreter"));
        }
        if ("AZURE_FOUNDRY_AGENT_TOOLS".equals(family)) {
            values.put("toolType", nullToEmpty(text(resource.properties().path("type"))));
        }
        if ("AZURE_ML_ENDPOINTS".equals(family)) {
            String authMode = text(resource.properties().path("authMode"));
            values.put("authMode", nullToEmpty(authMode));
            values.put("mlLocalAuthEnabled", "key".equalsIgnoreCase(authMode));
            values.put("traffic", toMap(resource.properties().path("traffic")));
        }
        if ("AZURE_ML_DEPLOYMENTS".equals(family)) {
            values.put("instanceType", nullToEmpty(text(resource.properties().path("instanceType"))));
            values.put("model", nullToEmpty(text(resource.properties().path("model"))));
            values.put("endpointComputeType",
                    nullToEmpty(text(resource.properties().path("endpointComputeType"))));
        }
        if ("AZURE_ML_JOBS".equals(family) || "AZURE_ML_PIPELINES".equals(family)) {
            values.put("jobType", nullToEmpty(text(resource.properties().path("jobType"))));
            values.put("status", nullToEmpty(text(resource.properties().path("status"))));
            values.put("experimentName", nullToEmpty(text(resource.properties().path("experimentName"))));
        }
        if ("AZURE_SEARCH_SERVICES".equals(family)) {
            boolean disableLocalAuth = resource.properties().path("disableLocalAuth").asBoolean(false);
            values.put("disableLocalAuth", disableLocalAuth);
            values.put("searchLocalAuthEnabled", !disableLocalAuth);
        }
        if ("AZURE_BOT_SERVICES".equals(family)) {
            String appType = text(resource.properties().path("msaAppType"));
            boolean managedIdentity = text(resource.identity().path("type")) != null;
            values.put("msaAppType", nullToEmpty(appType));
            values.put("managedIdentityAssigned", managedIdentity);
            values.put("botPasswordAuthWithoutManagedIdentity",
                    appType != null && !"UserAssignedMSI".equalsIgnoreCase(appType) && !managedIdentity);
        }
        if ("AZURE_DIAGNOSTIC_SETTINGS".equals(family)) {
            boolean logsEnabled = false;
            JsonNode logs = resource.properties().path("logs");
            if (logs.isArray()) {
                for (JsonNode log : logs) {
                    logsEnabled |= log.path("enabled").asBoolean(false);
                }
            }
            values.put("diagnosticLoggingEnabled", logsEnabled);
            values.put("hasDestination", text(resource.properties().path("workspaceId")) != null
                    || text(resource.properties().path("storageAccountId")) != null
                    || text(resource.properties().path("eventHubAuthorizationRuleId")) != null);
        }
        if ("AZURE_RBAC_GLOBAL".equals(family)) {
            values.put("principalId", nullToEmpty(text(resource.properties().path("principalId"))));
            values.put("principalType", nullToEmpty(text(resource.properties().path("principalType"))));
            values.put("roleDefinitionId", nullToEmpty(text(resource.properties().path("roleDefinitionId"))));
            values.put("assignmentScope", nullToEmpty(text(resource.properties().path("scope"))));
            values.put("conditionVersion", nullToEmpty(text(resource.properties().path("conditionVersion"))));
        }
        return values;
    }

    private boolean diagnosticLoggingEnabled(
            String resourceId,
            AzureAiManagementClient.DiscoverySnapshot snapshot
    ) {
        if (resourceId == null) return false;
        return snapshot.resources().getOrDefault("AZURE_DIAGNOSTIC_SETTINGS", List.of()).stream()
                .filter(setting -> resourceId.equalsIgnoreCase(setting.parentId()))
                .anyMatch(setting -> {
                    boolean enabled = false;
                    JsonNode logs = setting.properties().path("logs");
                    if (logs.isArray()) {
                        for (JsonNode log : logs) {
                            enabled |= log.path("enabled").asBoolean(false);
                        }
                    }
                    boolean destination = text(setting.properties().path("workspaceId")) != null
                            || text(setting.properties().path("storageAccountId")) != null
                            || text(setting.properties().path("eventHubAuthorizationRuleId")) != null;
                    return enabled && destination;
                });
    }

    private List<AzureResource> agentTools(List<AzureResource> agents) {
        List<AzureResource> tools = new ArrayList<>();
        for (AzureResource agent : agents) {
            JsonNode definitions = agent.properties().path("tools");
            if (!definitions.isArray()) continue;
            int index = 0;
            for (JsonNode tool : definitions) {
                String type = nullToEmpty(text(tool.path("type")));
                String id = agent.id() + "/tools/" + index++ + "-" + type.toLowerCase(Locale.ROOT);
                tools.add(new AzureResource(
                        id,
                        id,
                        type.isBlank() ? "Agent tool" : type,
                        "Microsoft.CognitiveServices/accounts/projects/applications/agentDeployments/tools",
                        "FoundryAgentTool",
                        agent.location(),
                        agent.subscriptionId(),
                        agent.resourceGroup(),
                        objectMapper.createObjectNode(),
                        tool,
                        objectMapper.createObjectNode(),
                        Map.of(),
                        agent.id()));
            }
        }
        return tools;
    }

    private ObservationEnvelopeV1 envelope(
            Tenant tenant,
            ConnectorSecret connector,
            UUID runId,
            ScopePayload payload
    ) {
        String region = payload.region();
        String scopeKey = "AZURE:" + connector.subscriptionId() + ":" + region + ":" + payload.family();
        String content = json(Map.of(
                "artifacts", payload.artifacts(),
                "relationships", payload.relationships(),
                "status", payload.status()));
        return new ObservationEnvelopeV1(
                AiSecurityObservationService.CONTRACT_VERSION,
                runId,
                connector.id(),
                tenant.getId(),
                "AZURE",
                connector.azureTenantId(),
                connector.subscriptionId(),
                region,
                payload.family(),
                scopeKey,
                0,
                1,
                runId + ":" + scopeKey + ":0",
                sha256(content),
                Instant.now(),
                payload.status(),
                payload.artifacts(),
                payload.relationships(),
                payload.diagnostics());
    }

    private ScopePayload unsupported(String family, String region, String code, String message) {
        return new ScopePayload(
                family,
                region,
                ScopeStatus.UNSUPPORTED,
                List.of(),
                List.of(),
                List.of(diagnostic(code, message, false, family)));
    }

    private Diagnostic diagnostic(String code, String message, boolean retryable, String family) {
        return new Diagnostic(
                code,
                message,
                retryable,
                permissionMatrix.requiredPermissions(family),
                UUID.randomUUID().toString());
    }

    private Map<String, AzureResource> index(Map<String, List<AzureResource>> resources) {
        Map<String, AzureResource> values = new LinkedHashMap<>();
        resources.values().forEach(list -> list.forEach(resource -> {
            if (resource.id() != null) values.put(resource.id(), resource);
        }));
        return values;
    }

    private AzureResource syntheticIdentity(AzureResource bot, String principalId) {
        String id = "azure-identity:" + principalId.toLowerCase(Locale.ROOT);
        return new AzureResource(
                id, id, principalId, "Microsoft.ManagedIdentity/principals", "ManagedIdentity",
                "GLOBAL", bot.subscriptionId(), bot.resourceGroup(),
                objectMapper.createObjectNode(), objectMapper.createObjectNode(),
                objectMapper.createObjectNode(), Map.of(), bot.id());
    }

    private AzureResource syntheticPrincipal(AzureResource assignment, String principalId) {
        String id = "azure-identity:" + principalId.toLowerCase(Locale.ROOT);
        return new AzureResource(
                id,
                id,
                principalId,
                "Microsoft.ManagedIdentity/principals",
                "AzurePrincipal",
                "GLOBAL",
                assignment.subscriptionId(),
                null,
                objectMapper.createObjectNode(),
                objectMapper.createObjectNode(),
                objectMapper.createObjectNode(),
                Map.of(),
                null);
    }

    private String artifactType(String family) {
        if ("AZURE_FOUNDRY_DEPLOYMENTS".equals(family) || "AZURE_ML_MODELS".equals(family)) return "AI_MODEL";
        if ("AZURE_FOUNDRY_AGENTS".equals(family) || "AZURE_BOT_SERVICES".equals(family)) return "AI_AGENT";
        return "OTHER_AI_ARTIFACT";
    }

    private String nativeKind(String family) {
        return family == null ? "AZURE_RESOURCE" : family.replaceFirst("^AZURE_", "AZURE_");
    }

    private String relationship(String family) {
        return switch (family) {
            case "AZURE_FOUNDRY_PROJECTS" -> "CONTAINS_PROJECT";
            case "AZURE_FOUNDRY_DEPLOYMENTS" -> "DEPLOYS_MODEL";
            case "AZURE_FOUNDRY_AGENT_TOOLS" -> "USES_TOOL";
            case "AZURE_ML_DEPLOYMENTS" -> "HAS_DEPLOYMENT";
            case "AZURE_ML_PIPELINES" -> "RUNS_PIPELINE";
            case "AZURE_BOT_CHANNELS" -> "HAS_CHANNEL";
            case "AZURE_DIAGNOSTIC_SETTINGS" -> "LOGS_TO";
            default -> "CONTAINS_RESOURCE";
        };
    }

    private String resourceFamily(String type) {
        if (type == null) return null;
        String normalized = type.toLowerCase(Locale.ROOT);
        if (normalized.equals("microsoft.cognitiveservices/accounts")) return "AZURE_AI_ACCOUNTS";
        if (normalized.equals("microsoft.cognitiveservices/accounts/projects")) return "AZURE_FOUNDRY_PROJECTS";
        if (normalized.equals("microsoft.cognitiveservices/accounts/deployments")) {
            return "AZURE_FOUNDRY_DEPLOYMENTS";
        }
        if (normalized.contains("/agentdeployments")) return "AZURE_FOUNDRY_AGENTS";
        if (normalized.equals("microsoft.machinelearningservices/workspaces")) return "AZURE_ML_WORKSPACES";
        if (normalized.contains("/models")) return "AZURE_ML_MODELS";
        if (normalized.contains("/onlineendpoints/") && normalized.endsWith("/deployments")) {
            return "AZURE_ML_DEPLOYMENTS";
        }
        if (normalized.contains("/onlineendpoints")) return "AZURE_ML_ENDPOINTS";
        if (normalized.contains("/computes")) return "AZURE_ML_COMPUTE";
        if (normalized.contains("/jobs")) return "AZURE_ML_JOBS";
        if (normalized.equals("microsoft.search/searchservices")) return "AZURE_SEARCH_SERVICES";
        if (normalized.equals("microsoft.botservice/botservices")) return "AZURE_BOT_SERVICES";
        if (normalized.endsWith("/channels")) return "AZURE_BOT_CHANNELS";
        if (normalized.equals("microsoft.insights/diagnosticsettings")) return "AZURE_DIAGNOSTIC_SETTINGS";
        if (normalized.equals("microsoft.managedidentity/principals")) return "AZURE_BOT_IDENTITIES";
        return "AZURE_SUPPORTING_RESOURCE";
    }

    private List<String> scopeRegions(
            String family,
            ConnectorSecret connector,
            List<AzureResource> resources
    ) {
        if (isGlobalFamily(family)) {
            return List.of("GLOBAL");
        }
        LinkedHashSet<String> regions = new LinkedHashSet<>();
        if (connector.regions() != null) {
            connector.regions().stream()
                    .filter(this::hasText)
                    .map(value -> value.toLowerCase(Locale.ROOT))
                    .forEach(regions::add);
        }
        if (!regions.isEmpty()) {
            return List.copyOf(regions);
        }
        resources.stream()
                .map(AzureResource::location)
                .filter(this::hasText)
                .filter(value -> !"GLOBAL".equalsIgnoreCase(value))
                .map(value -> value.toLowerCase(Locale.ROOT))
                .forEach(regions::add);
        return List.copyOf(regions);
    }

    private boolean isGlobalFamily(String family) {
        return family.endsWith("_GLOBAL") || family.startsWith("AZURE_BOT");
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private boolean hasTool(JsonNode properties, String expected) {
        JsonNode tools = properties.path("tools");
        if (!tools.isArray()) return false;
        for (JsonNode tool : tools) {
            String type = text(tool.path("type"));
            if (expected.equalsIgnoreCase(type)) return true;
        }
        return false;
    }

    private int size(JsonNode node) {
        return node != null && node.isArray() ? node.size() : 0;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> toMap(JsonNode node) {
        return node == null || !node.isObject()
                ? Map.of()
                : objectMapper.convertValue(node, Map.class);
    }

    private String text(JsonNode node) {
        return node == null || node.isMissingNode() || node.isNull() || node.asText().isBlank()
                ? null : node.asText();
    }

    private String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    private String json(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception exception) {
            throw new IllegalStateException("Unable to serialize Azure AI Security observation", exception);
        }
    }

    private String sha256(String value) {
        try {
            return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception exception) {
            throw new IllegalStateException("Unable to hash Azure AI Security observation", exception);
        }
    }

    @Override
    public String failureCode(Exception exception) {
        if (exception instanceof AzureApiException azureException) {
            return azureException.failure().code();
        }
        if (exception instanceof AiSecurityAzureAdmissionService.AdmissionException) {
            return "THROTTLED";
        }
        return AiSecurityDiscoveryProvider.super.failureCode(exception);
    }

    @Override
    public String safeFailureMessage(String code) {
        return switch (code) {
            case "AZURE_AUTHENTICATION_FAILED" -> "Azure authentication failed";
            case "AZURE_TENANT_MISMATCH" -> "Azure tenant does not match the connector";
            case "ACCESS_DENIED" -> "Azure permissions are insufficient for discovery";
            case "THROTTLED" -> "Azure temporarily throttled AI Security discovery";
            case "TIMEOUT" -> "Azure discovery timed out";
            default -> "Azure AI Security discovery could not be completed";
        };
    }

    private record ScopePayload(
            String family,
            String region,
            ScopeStatus status,
            List<ArtifactObservation> artifacts,
            List<RelationshipObservation> relationships,
            List<Diagnostic> diagnostics
    ) {
    }

    public record DiscoveryResult(UUID runId, int artifactsObserved, int incompleteScopes) {
    }
}
