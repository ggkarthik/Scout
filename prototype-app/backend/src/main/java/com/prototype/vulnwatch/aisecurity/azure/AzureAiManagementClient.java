package com.prototype.vulnwatch.aisecurity.azure;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenCredential;
import com.azure.core.credential.TokenRequestContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.aisecurity.service.AiGridProviderCallCounter;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;
import org.springframework.stereotype.Component;

@Component
public class AzureAiManagementClient {

    private static final String MANAGEMENT_HOST = "management.azure.com";
    private static final String MANAGEMENT_SCOPE = "https://management.azure.com/.default";
    private static final String SEARCH_SCOPE = "https://search.azure.com/.default";
    private static final String FOUNDRY_SCOPE = "https://ai.azure.com/.default";
    private static final int MAX_PAGES = 100;
    private static final int MAX_BODY_CHARS = 4_000_000;
    private static final int MAX_ATTEMPTS = 3;
    private static final Duration MAX_RETRY_DELAY = Duration.ofSeconds(5);

    private final HttpClient http;
    private final ObjectMapper objectMapper;
    private final AzurePolicyPermissionMatrix permissionMatrix;
    private final AiGridProviderCallCounter providerCalls;

    @org.springframework.beans.factory.annotation.Autowired
    public AzureAiManagementClient(
            ObjectMapper objectMapper,
            AzurePolicyPermissionMatrix permissionMatrix,
            AiGridProviderCallCounter providerCalls
    ) {
        this.objectMapper = objectMapper;
        this.permissionMatrix = permissionMatrix;
        this.providerCalls = providerCalls;
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    AzureAiManagementClient(ObjectMapper objectMapper, AzurePolicyPermissionMatrix permissionMatrix) {
        this(objectMapper, permissionMatrix, new AiGridProviderCallCounter());
    }

    public DiscoverySnapshot discover(TokenCredential credential, String subscriptionId) {
        return discover(credential, subscriptionId, AiSecurityAzureConnectorService.RESOURCE_FAMILIES, false);
    }

    public DiscoverySnapshot discover(
            TokenCredential credential,
            String subscriptionId,
            Set<String> requestedFamilies,
            boolean previewAgentsEnabled
    ) {
        Set<String> requested = requestedFamilies == null ? Set.of() : Set.copyOf(requestedFamilies);
        Map<String, List<AzureResource>> resources = new LinkedHashMap<>();
        Map<String, AzureApiFailure> failures = new LinkedHashMap<>();
        for (String family : AiSecurityAzureConnectorService.RESOURCE_FAMILIES) {
            resources.put(family, new ArrayList<>());
        }

        List<AzureResource> subscriptionResources;
        try {
            String url = "https://" + MANAGEMENT_HOST + "/subscriptions/"
                    + encode(subscriptionId) + "/resources?api-version=2021-04-01";
            subscriptionResources = list(credential, url).stream()
                    .map(node -> resource(node, subscriptionId))
                    .filter(resource -> resource.id() != null && resource.type() != null)
                    .toList();
        } catch (AzureApiException exception) {
            AzureApiFailure failure = exception.failure();
            AiSecurityAzureConnectorService.RESOURCE_FAMILIES.forEach(family -> failures.put(family, failure));
            return new DiscoverySnapshot(resources, failures);
        }

        for (AzureResource resource : subscriptionResources) {
            String family = family(resource.type());
            if (family != null && neededBaseFamily(family, requested)) {
                resources.get(family).add(enrich(credential, resource, failures, family));
            }
        }

        collectRequestedChild(credential, requested, resources.get("AZURE_AI_ACCOUNTS"),
                "projects", "AZURE_FOUNDRY_PROJECTS", resources, failures);
        collectRequestedChild(credential, requested, resources.get("AZURE_FOUNDRY_PROJECTS"),
                "connections", "AZURE_FOUNDRY_CONNECTIONS", resources, failures);
        collectRequestedChild(credential, requested, resources.get("AZURE_AI_ACCOUNTS"),
                "deployments", "AZURE_FOUNDRY_DEPLOYMENTS", resources, failures);
        collectRequestedChild(credential, requested, resources.get("AZURE_AI_ACCOUNTS"),
                "raiPolicies", "AZURE_RAI_POLICIES", resources, failures);
        if (previewAgentsEnabled && requested.stream().anyMatch(family -> family.startsWith("AZURE_FOUNDRY_AGENT"))) {
            collectFoundryAgents(credential, resources.get("AZURE_FOUNDRY_PROJECTS"), resources, failures);
        }
        collectRequestedChild(credential, requested, resources.get("AZURE_ML_WORKSPACES"),
                "models", "AZURE_ML_MODELS", resources, failures);
        collectRequestedChild(credential, requested, resources.get("AZURE_ML_WORKSPACES"),
                "onlineEndpoints", "AZURE_ML_ENDPOINTS", resources, failures);
        collectRequestedChild(credential, requested, resources.get("AZURE_ML_ENDPOINTS"),
                "deployments", "AZURE_ML_DEPLOYMENTS", resources, failures);
        collectRequestedChild(credential, requested, resources.get("AZURE_ML_WORKSPACES"),
                "computes", "AZURE_ML_COMPUTE", resources, failures);
        if (requested.contains("AZURE_ML_JOBS") || requested.contains("AZURE_ML_PIPELINES")) {
            collectChildren(credential, resources.get("AZURE_ML_WORKSPACES"),
                    "jobs", "AZURE_ML_JOBS", resources, failures);
            partitionPipelineJobs(resources);
        }
        if (requested.stream().anyMatch(AzureAiManagementClient::isSearchDefinitionFamily)) {
            collectSearchDefinitions(credential, requested, resources.get("AZURE_SEARCH_SERVICES"), resources, failures);
        }
        collectRequestedChild(credential, requested, resources.get("AZURE_BOT_SERVICES"),
                "channels", "AZURE_BOT_CHANNELS", resources, failures);

        if (requested.contains("AZURE_DIAGNOSTIC_SETTINGS")) {
            collectDiagnostics(credential, subscriptionResources, resources, failures);
        }
        if (requested.contains("AZURE_RBAC_GLOBAL")) {
            collectSubscriptionRbac(credential, subscriptionId, resources, failures);
        }
        return new DiscoverySnapshot(resources, failures);
    }

    /**
     * Azure AI Search definitions are read through the service data plane.  This deliberately
     * uses only collection GET endpoints: it never calls documents, query, key, or index
     * mutation endpoints.
     */
    private void collectSearchDefinitions(
            TokenCredential credential,
            Set<String> requested,
            List<AzureResource> services,
            Map<String, List<AzureResource>> resources,
            Map<String, AzureApiFailure> failures
    ) {
        if (services == null) return;
        Map<String, String> paths = Map.of(
                "AZURE_SEARCH_INDEXES", "indexes",
                "AZURE_SEARCH_SKILLSETS", "skillsets",
                "AZURE_SEARCH_INDEXERS", "indexers",
                "AZURE_SEARCH_DATA_SOURCES", "datasources");
        for (AzureResource service : services) {
            String endpoint = text(service.properties().path("endpoint"));
            if (endpoint == null) endpoint = text(service.properties().path("hostName"));
            if (endpoint == null) endpoint = service.name() == null ? null : service.name() + ".search.windows.net";
            if (endpoint == null) continue;
            String base = endpoint.startsWith("https://") ? endpoint : "https://" + endpoint;
            for (Map.Entry<String, String> entry : paths.entrySet()) {
                String family = entry.getKey();
                if (!requested.contains(family) || failures.containsKey(family)) continue;
                try {
                    for (JsonNode node : searchList(credential, base + "/" + entry.getValue() + "?api-version=2024-07-01")) {
                        AzureResource definition = searchResource(node, service, family).withParentId(service.id());
                        resources.get(family).add(definition);
                    }
                } catch (AzureApiException exception) {
                    failures.put(family, exception.failure());
                }
            }
        }
    }

    private static boolean isSearchDefinitionFamily(String family) {
        return "AZURE_SEARCH_INDEXES".equals(family) || "AZURE_SEARCH_SKILLSETS".equals(family)
                || "AZURE_SEARCH_INDEXERS".equals(family) || "AZURE_SEARCH_DATA_SOURCES".equals(family);
    }

    /** Uses only GET /agents and published definitions; it never invokes agents, models, or tools. */
    private void collectFoundryAgents(
            TokenCredential credential, List<AzureResource> projects,
            Map<String, List<AzureResource>> resources, Map<String, AzureApiFailure> failures
    ) {
        if (projects == null || failures.containsKey("AZURE_FOUNDRY_AGENTS")) return;
        for (AzureResource project : projects) {
            String endpoint = foundryProjectEndpoint(project);
            if (endpoint == null) continue;
            try {
                for (JsonNode agent : foundryList(credential, endpoint + "/agents?api-version=v1")) {
                    resources.get("AZURE_FOUNDRY_AGENTS").add(foundryAgentResource(agent, project));
                }
            } catch (AzureApiException exception) {
                failures.put("AZURE_FOUNDRY_AGENTS", exception.failure());
                return;
            }
        }
    }

    private String foundryProjectEndpoint(AzureResource project) {
        if (project.id() == null) return null;
        String lowered = project.id().toLowerCase(Locale.ROOT);
        int accountStart = lowered.indexOf("/accounts/");
        int projectStart = lowered.indexOf("/projects/");
        if (accountStart < 0 || projectStart <= accountStart) return null;
        String account = project.id().substring(accountStart + "/accounts/".length(), projectStart);
        String projectName = project.id().substring(projectStart + "/projects/".length());
        if (account.isBlank() || projectName.isBlank() || projectName.contains("/")) return null;
        return "https://" + account + ".services.ai.azure.com/api/projects/" + encode(projectName);
    }

    private List<JsonNode> foundryList(TokenCredential credential, String url) {
        List<JsonNode> values = new ArrayList<>();
        JsonNode data = get(credential, url).path("data");
        if (data.isArray()) data.forEach(values::add);
        return values;
    }

    private AzureResource foundryAgentResource(JsonNode agent, AzureResource project) {
        String name = text(agent.path("name"));
        String id = project.id() + "/agents/" + (name == null ? "unnamed" : name);
        com.fasterxml.jackson.databind.node.ObjectNode properties = objectMapper.createObjectNode();
        JsonNode definition = agent.path("versions").path("latest").path("definition");
        if (definition.isObject()) properties.setAll((com.fasterxml.jackson.databind.node.ObjectNode) definition);
        String model = text(definition.path("model"));
        if (model != null) properties.put("modelDeploymentName", model);
        String version = text(agent.path("versions").path("latest").path("version"));
        if (version != null) properties.put("agentVersion", version);
        return new AzureResource(id.toLowerCase(Locale.ROOT), id, name,
                "Microsoft.Foundry/projects/agents", "FoundryPromptAgent", project.location(),
                project.subscriptionId(), project.resourceGroup(), objectMapper.createObjectNode(), properties,
                objectMapper.createObjectNode(), Map.of(), project.id());
    }

    private List<JsonNode> searchList(TokenCredential credential, String initialUrl) {
        List<JsonNode> values = new ArrayList<>();
        String next = initialUrl;
        for (int page = 0; next != null; page++) {
            if (page >= MAX_PAGES) throw new AzureApiException(new AzureApiFailure(
                    "INVALID_CONFIGURATION", "Azure Search pagination limit was exceeded", false, 0));
            JsonNode response = get(credential, next);
            JsonNode pageValues = response.path("value");
            if (pageValues.isArray()) pageValues.forEach(values::add);
            next = text(response.path("@odata.nextLink"));
            if (next != null) validateSearchUri(URI.create(next));
        }
        return values;
    }

    private AzureResource searchResource(JsonNode node, AzureResource service, String family) {
        String name = text(node.path("name"));
        String id = service.id() + "/" + family.toLowerCase(Locale.ROOT) + "/" + (name == null ? "unnamed" : name);
        return new AzureResource(id.toLowerCase(Locale.ROOT), id, name, family, null, service.location(),
                service.subscriptionId(), service.resourceGroup(), objectMapper.createObjectNode(), node,
                objectMapper.createObjectNode(), Map.of(), null);
    }

    private void collectSubscriptionRbac(
            TokenCredential credential,
            String subscriptionId,
            Map<String, List<AzureResource>> resources,
            Map<String, AzureApiFailure> failures
    ) {
        try {
            String path = "/subscriptions/" + encode(subscriptionId)
                    + "/providers/Microsoft.Authorization/roleAssignments";
            for (JsonNode node : list(credential, managementUrl(
                    path, permissionMatrix.family("AZURE_RBAC_GLOBAL").apiVersion()))) {
                resources.get("AZURE_RBAC_GLOBAL").add(resource(node, subscriptionId)
                        .withLocation("GLOBAL"));
            }
        } catch (AzureApiException exception) {
            failures.put("AZURE_RBAC_GLOBAL", exception.failure());
        }
    }

    private boolean neededBaseFamily(String family, Set<String> requested) {
        if (requested.contains(family)) return true;
        if ("AZURE_AI_ACCOUNTS".equals(family)) {
            return requested.stream().anyMatch(value -> value.startsWith("AZURE_FOUNDRY")
                    || value.startsWith("AZURE_RAI"));
        }
        if ("AZURE_ML_WORKSPACES".equals(family)) {
            return requested.stream().anyMatch(value -> value.startsWith("AZURE_ML"));
        }
        if ("AZURE_BOT_SERVICES".equals(family)) {
            return requested.stream().anyMatch(value -> value.startsWith("AZURE_BOT"));
        }
        return false;
    }

    private void collectRequestedChild(
            TokenCredential credential,
            Set<String> requested,
            List<AzureResource> parents,
            String childPath,
            String family,
            Map<String, List<AzureResource>> resources,
            Map<String, AzureApiFailure> failures
    ) {
        if (requested.contains(family)
                || ("AZURE_FOUNDRY_PROJECTS".equals(family)
                        && requested.stream().anyMatch(value -> value.startsWith("AZURE_FOUNDRY_AGENT")))) {
            collectChildren(credential, parents, childPath, family, resources, failures);
        }
    }

    private void collectChildren(
            TokenCredential credential,
            List<AzureResource> parents,
            String childPath,
            String family,
            Map<String, List<AzureResource>> resources,
            Map<String, AzureApiFailure> failures
    ) {
        if (parents == null || failures.containsKey(family)) {
            return;
        }
        List<AzureResource> collected = resources.get(family);
        for (AzureResource parent : parents) {
            String childType = parent.type() + "/" + childPath.toLowerCase(Locale.ROOT);
            String version = apiVersion(childType);
            try {
                for (JsonNode node : list(credential, managementUrl(parent.id() + "/" + childPath, version))) {
                    AzureResource child = resource(node, parent.subscriptionId());
                    if (child.location() == null || "GLOBAL".equalsIgnoreCase(child.location())) {
                        child = child.withLocation(parent.location());
                    }
                    collected.add(child.withParentId(parent.id()));
                }
            } catch (AzureApiException exception) {
                failures.put(family, exception.failure());
                return;
            }
        }
    }

    private void partitionPipelineJobs(Map<String, List<AzureResource>> resources) {
        List<AzureResource> jobs = resources.get("AZURE_ML_JOBS");
        List<AzureResource> pipelines = resources.get("AZURE_ML_PIPELINES");
        if (jobs == null || pipelines == null) {
            return;
        }
        List<AzureResource> pipelineJobs = jobs.stream().filter(this::isPipelineJob).toList();
        pipelines.addAll(pipelineJobs);
        jobs.removeAll(pipelineJobs);
    }

    boolean isPipelineJob(AzureResource resource) {
        String jobType = text(resource.properties().path("jobType"));
        String componentId = text(resource.properties().path("componentId"));
        return "PIPELINE".equalsIgnoreCase(jobType)
                || (componentId != null && componentId.toLowerCase(Locale.ROOT).contains("/components/"));
    }

    private void collectDiagnostics(
            TokenCredential credential,
            List<AzureResource> resourcesToInspect,
            Map<String, List<AzureResource>> resources,
            Map<String, AzureApiFailure> failures
    ) {
        List<AzureResource> diagnostics = resources.get("AZURE_DIAGNOSTIC_SETTINGS");
        for (AzureResource resource : resourcesToInspect) {
            if (family(resource.type()) == null) {
                continue;
            }
            try {
                String path = resource.id() + "/providers/Microsoft.Insights/diagnosticSettings";
                for (JsonNode node : list(credential, managementUrl(
                        path, permissionMatrix.family("AZURE_DIAGNOSTIC_SETTINGS").apiVersion()))) {
                    AzureResource diagnostic = resource(node, resource.subscriptionId())
                            .withLocation(resource.location())
                            .withParentId(resource.id());
                    diagnostics.add(diagnostic);
                }
            } catch (AzureApiException exception) {
                failures.putIfAbsent("AZURE_DIAGNOSTIC_SETTINGS", exception.failure());
            }
        }
    }

    private AzureResource enrich(
            TokenCredential credential,
            AzureResource resource,
            Map<String, AzureApiFailure> failures,
            String family
    ) {
        try {
            JsonNode node = get(credential, managementUrl(resource.id(), apiVersion(resource.type())));
            return resource(node, resource.subscriptionId());
        } catch (AzureApiException exception) {
            failures.putIfAbsent(family, exception.failure());
            return resource;
        }
    }

    private List<JsonNode> list(TokenCredential credential, String initialUrl) {
        List<JsonNode> values = new ArrayList<>();
        Set<String> visited = new LinkedHashSet<>();
        String next = initialUrl;
        for (int page = 0; next != null; page++) {
            if (page >= MAX_PAGES || !visited.add(next)) {
                throw new AzureApiException(new AzureApiFailure(
                        "INVALID_CONFIGURATION", "Azure pagination limit was exceeded", false, 0));
            }
            JsonNode response = get(credential, next);
            JsonNode pageValues = response.path("value");
            if (pageValues.isArray()) {
                pageValues.forEach(values::add);
            } else if (!response.isMissingNode() && !response.isNull()) {
                values.add(response);
            }
            String candidate = text(response.path("nextLink"));
            if (candidate != null) {
                validateManagementUri(URI.create(candidate));
            }
            next = candidate;
        }
        return values;
    }

    private JsonNode get(TokenCredential credential, String url) {
        URI uri = URI.create(url);
        validateAllowedUri(uri);
        AzureApiException terminal = null;
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            HttpHeaders responseHeaders = HttpHeaders.of(Map.of(), (name, value) -> true);
            try {
                HttpRequest request = HttpRequest.newBuilder(uri)
                        .timeout(Duration.ofSeconds(30))
                        .header("Authorization", "Bearer " + bearerToken(credential, uri.getHost()))
                        .header("Accept", "application/json")
                        .GET()
                        .build();
                providerCalls.increment();
                HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
                responseHeaders = response.headers();
                String body = response.body() == null ? "" : response.body();
                if (body.length() > MAX_BODY_CHARS) {
                    throw new AzureApiException(new AzureApiFailure(
                            "INVALID_CONFIGURATION", "Azure response exceeded the allowed size",
                            false, response.statusCode()));
                }
                if (response.statusCode() < 200 || response.statusCode() >= 300) {
                    throw new AzureApiException(failure(response.statusCode(), body));
                }
                return body.isBlank() ? objectMapper.createObjectNode() : objectMapper.readTree(body);
            } catch (AzureApiException exception) {
                terminal = exception;
            } catch (java.net.http.HttpTimeoutException exception) {
                terminal = new AzureApiException(
                        new AzureApiFailure("TIMEOUT", "Azure request timed out", true, 0));
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                throw new AzureApiException(new AzureApiFailure(
                        "PROVIDER_UNAVAILABLE", "Azure request was interrupted", true, 0));
            } catch (Exception exception) {
                terminal = new AzureApiException(new AzureApiFailure(
                        "PROVIDER_UNAVAILABLE", "Azure request could not be completed", true, 0));
            }
            if (terminal == null || !terminal.failure().retryable() || attempt == MAX_ATTEMPTS) {
                throw terminal;
            }
            sleep(retryDelay(responseHeaders, attempt));
        }
        throw terminal;
    }

    Duration retryDelay(HttpHeaders headers, int attempt) {
        long requestedMillis = headers.firstValue("x-ms-retry-after-ms")
                .map(this::positiveLong)
                .orElseGet(() -> headers.firstValue("Retry-After")
                        .map(this::positiveLong)
                        .map(seconds -> seconds * 1_000L)
                        .orElse(0L));
        long fallbackMillis = 250L * (1L << Math.max(0, attempt - 1))
                + ThreadLocalRandom.current().nextLong(0, 251);
        long delayMillis = requestedMillis > 0 ? requestedMillis : fallbackMillis;
        return Duration.ofMillis(Math.min(delayMillis, MAX_RETRY_DELAY.toMillis()));
    }

    private long positiveLong(String value) {
        try {
            return Math.max(0L, Long.parseLong(value.trim()));
        } catch (RuntimeException exception) {
            return 0L;
        }
    }

    private void sleep(Duration delay) {
        try {
            Thread.sleep(delay.toMillis());
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new AzureApiException(new AzureApiFailure(
                    "PROVIDER_UNAVAILABLE", "Azure retry was interrupted", true, 0));
        }
    }

    private AzureApiFailure failure(int status, String body) {
        String providerCode = null;
        try {
            providerCode = text(objectMapper.readTree(body).path("error").path("code"));
        } catch (Exception ignored) {
            // The sanitized status-based code remains authoritative.
        }
        if (status == 401) {
            return new AzureApiFailure("AZURE_AUTHENTICATION_FAILED", "Azure authentication failed", false, status);
        }
        if (status == 403) {
            return new AzureApiFailure("ACCESS_DENIED", "Azure permission is missing", false, status);
        }
        if (status == 404 && "MissingSubscriptionRegistration".equalsIgnoreCase(providerCode)) {
            return new AzureApiFailure(
                    "RESOURCE_PROVIDER_NOT_REGISTERED", "Azure resource provider is not registered", false, status);
        }
        if (status == 429) {
            return new AzureApiFailure("THROTTLED", "Azure temporarily throttled discovery", true, status);
        }
        return new AzureApiFailure("PROVIDER_UNAVAILABLE", "Azure API request failed", status >= 500, status);
    }

    private AzureResource resource(JsonNode node, String subscriptionId) {
        String id = text(node.path("id"));
        String type = text(node.path("type"));
        String location = text(node.path("location"));
        return new AzureResource(
                canonicalArmId(id),
                id,
                text(node.path("name")),
                type,
                text(node.path("kind")),
                location == null ? "GLOBAL" : location.toLowerCase(Locale.ROOT),
                subscriptionId,
                resourceGroup(id),
                node.path("identity"),
                node.path("properties"),
                node.path("sku"),
                stringMap(node.path("tags")),
                null);
    }

    String family(String type) {
        if (type == null) return null;
        String normalized = type.toLowerCase(Locale.ROOT);
        if (normalized.equals("microsoft.cognitiveservices/accounts")) return "AZURE_AI_ACCOUNTS";
        if (normalized.equals("microsoft.cognitiveservices/accounts/projects")) return "AZURE_FOUNDRY_PROJECTS";
        if (normalized.equals("microsoft.cognitiveservices/accounts/deployments")) return "AZURE_FOUNDRY_DEPLOYMENTS";
        if (normalized.equals("microsoft.cognitiveservices/accounts/raipolicies")) return "AZURE_RAI_POLICIES";
        if (normalized.equals("microsoft.cognitiveservices/accounts/projects/connections")) return "AZURE_FOUNDRY_CONNECTIONS";
        if (normalized.equals("microsoft.storage/storageaccounts")) return "AZURE_STORAGE_ACCOUNTS";
        if (normalized.contains("/agentdeployments")) return "AZURE_FOUNDRY_AGENTS";
        if (normalized.equals("microsoft.foundry/projects/agents")) return "AZURE_FOUNDRY_AGENTS";
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
        if (normalized.equals("microsoft.authorization/roleassignments")) return "AZURE_RBAC_GLOBAL";
        return null;
    }

    private String apiVersion(String type) {
        String resourceFamily = family(type);
        return resourceFamily == null
                ? "2021-04-01"
                : permissionMatrix.family(resourceFamily).apiVersion();
    }

    private String managementUrl(String path, String apiVersion) {
        return "https://" + MANAGEMENT_HOST + path + "?api-version=" + encode(apiVersion);
    }

    void validateManagementUri(URI uri) {
        if (!"https".equalsIgnoreCase(uri.getScheme())
                || uri.getHost() == null
                || !MANAGEMENT_HOST.equalsIgnoreCase(uri.getHost())
                || uri.getUserInfo() != null) {
            throw new AzureApiException(new AzureApiFailure(
                    "INVALID_CONFIGURATION", "Azure continuation host is not allowed", false, 0));
        }
    }

    private void validateAllowedUri(URI uri) {
        if (MANAGEMENT_HOST.equalsIgnoreCase(uri.getHost())) {
            validateManagementUri(uri);
        } else if (isFoundryHost(uri.getHost())) {
            validateFoundryUri(uri);
        } else {
            validateSearchUri(uri);
        }
    }

    void validateSearchUri(URI uri) {
        String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT);
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getUserInfo() != null
                || !(host.endsWith(".search.windows.net") || host.endsWith(".search.azure.com"))) {
            throw new AzureApiException(new AzureApiFailure(
                    "INVALID_CONFIGURATION", "Azure Search endpoint is not allowed", false, 0));
        }
    }

    void validateFoundryUri(URI uri) {
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getUserInfo() != null || !isFoundryHost(uri.getHost())) {
            throw new AzureApiException(new AzureApiFailure(
                    "INVALID_CONFIGURATION", "Azure Foundry endpoint is not allowed", false, 0));
        }
    }

    private boolean isFoundryHost(String host) {
        return host != null && host.toLowerCase(Locale.ROOT).endsWith(".services.ai.azure.com");
    }

    private String bearerToken(TokenCredential credential, String host) {
        String scope = host != null && (host.endsWith(".search.windows.net") || host.endsWith(".search.azure.com"))
                ? SEARCH_SCOPE : isFoundryHost(host) ? FOUNDRY_SCOPE : MANAGEMENT_SCOPE;
        AccessToken token = credential.getToken(new TokenRequestContext().addScopes(scope))
                .block(Duration.ofSeconds(30));
        if (token == null || token.getToken() == null || token.getToken().isBlank()) {
            throw new AzureApiException(new AzureApiFailure(
                    "AZURE_AUTHENTICATION_FAILED", "Unable to acquire Azure token", false, 0));
        }
        return token.getToken();
    }

    private Map<String, String> stringMap(JsonNode node) {
        Map<String, String> values = new LinkedHashMap<>();
        if (node != null && node.isObject()) {
            node.fields().forEachRemaining(entry -> values.put(entry.getKey(), entry.getValue().asText()));
        }
        return values;
    }

    private String resourceGroup(String id) {
        if (id == null) return null;
        String lower = id.toLowerCase(Locale.ROOT);
        String marker = "/resourcegroups/";
        int start = lower.indexOf(marker);
        if (start < 0) return null;
        String remainder = id.substring(start + marker.length());
        int end = remainder.indexOf('/');
        return end < 0 ? remainder : remainder.substring(0, end);
    }

    private String canonicalArmId(String id) {
        return id == null ? null : id.trim().toLowerCase(Locale.ROOT);
    }

    private String text(JsonNode node) {
        return node == null || node.isMissingNode() || node.isNull() || node.asText().isBlank()
                ? null : node.asText();
    }

    private String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    public record DiscoverySnapshot(
            Map<String, List<AzureResource>> resources,
            Map<String, AzureApiFailure> failures
    ) {
    }

    public record AzureResource(
            String id,
            String originalId,
            String name,
            String type,
            String kind,
            String location,
            String subscriptionId,
            String resourceGroup,
            JsonNode identity,
            JsonNode properties,
            JsonNode sku,
            Map<String, String> tags,
            String parentId
    ) {
        AzureResource withLocation(String replacement) {
            return new AzureResource(id, originalId, name, type, kind, replacement, subscriptionId,
                    resourceGroup, identity, properties, sku, tags, parentId);
        }

        AzureResource withParentId(String replacement) {
            return new AzureResource(id, originalId, name, type, kind, location, subscriptionId,
                    resourceGroup, identity, properties, sku, tags, replacement);
        }
    }

    public record AzureApiFailure(String code, String message, boolean retryable, int statusCode) {
    }

    public static final class AzureApiException extends RuntimeException {
        private final AzureApiFailure failure;

        AzureApiException(AzureApiFailure failure) {
            super(failure.message());
            this.failure = failure;
        }

        public AzureApiFailure failure() {
            return failure;
        }
    }
}
