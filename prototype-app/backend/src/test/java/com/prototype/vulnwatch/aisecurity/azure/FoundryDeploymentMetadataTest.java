package com.prototype.vulnwatch.aisecurity.azure;

import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.aisecurity.azure.AzureAiManagementClient.AzureResource;
import com.prototype.vulnwatch.aisecurity.azure.AzureAiManagementClient.AzureApiFailure;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class FoundryDeploymentMetadataTest {
    private final ObjectMapper json = new ObjectMapper();
    private final AzureAiManagementClient client = new AzureAiManagementClient(json, new AzurePolicyPermissionMatrix());
    private AzureResource resource(String id, String parent, String properties) throws Exception {
        return new AzureResource(id,id,"support","Microsoft.Foundry/projects/agents",null,"eastus","subscription","rg",
                json.createObjectNode(), json.readTree(properties), json.createObjectNode(), Map.of(),parent);
    }
    @Test void resolvesExplicitAndDefaultLatestVersionSelectorsWithoutDefinitionInference() throws Exception {
        var agent = resource("project/agents/support","project","{}");
        var explicit = client.foundryRouteResource(json.readTree("""
                {"agent_endpoint":{"protocol_configuration":{"responses":{}},"version_selector":{
                  "version_selection_rules":[{"type":"FixedRatio","agent_version":"4","traffic_percentage":100}]}},
                 "versions":{"latest":{"version":"5","definition":{"kind":"prompt"}}}}
                """),agent);
        assertEquals("READY", explicit.properties().path("status").asText());
        assertEquals("4", explicit.properties().path("routedVersions").get(0).asText());
        var latest = client.foundryRouteResource(json.readTree("""
                {"agent_endpoint":{"protocol_configuration":{"responses":{}}},"versions":{"latest":{"version":"5"}}}
                """),agent);
        assertEquals("5", latest.properties().path("routedVersions").get(0).asText());
        assertEquals("UNSUPPORTED_API", client.foundryRouteResource(json.readTree("{\"versions\":{\"latest\":{\"version\":\"5\"}}}"),agent)
                .properties().path("deploymentEvidenceReason").asText());
    }
    @Test void retainsZeroTrafficAndUnsupportedSelectorsAsDistinctEvidence() throws Exception {
        var agent = resource("project/agents/support","project","{}");
        var zero = client.foundryRouteResource(json.readTree("""
                {"agent_endpoint":{"protocol_configuration":{"responses":{}},"version_selector":{
                    "version_selection_rules":[{"type":"FixedRatio","agent_version":"1","traffic_percentage":0}]}}}
                """),agent);
        assertEquals("ZERO_TRAFFIC_ALLOCATION", zero.properties().path("status").asText());
        var malformed = client.foundryRouteResource(json.readTree("""
                {"agent_endpoint":{"protocol_configuration":{"responses":{}},"version_selector":{"type":"Unknown"}},
                 "versions":{"latest":{"version":"1"}}}
                """),agent);
        assertEquals("AMBIGUOUS_ROUTE_STATE",malformed.properties().path("deploymentEvidenceReason").asText());
        var unknown = client.foundryRouteResource(json.readTree("""
                {"agent_endpoint":{"protocol_configuration":{"responses":{}},"version_selector":{
                    "version_selection_rules":[{"type":"Unknown","agent_version":"1","traffic_percentage":100}]}}}
                """),agent);
        assertEquals("AMBIGUOUS_ROUTE_STATE",unknown.properties().path("deploymentEvidenceReason").asText());
    }
    @Test void legacyApplicationRequiresExplicitAgentReferenceAndRunningDeployment() throws Exception {
        var agent = resource("project/agents/support","project","{}");
        var app = resource("project/applications/app","project","""
                {"agents":[{"agentName":"support"}],"trafficRoutingPolicy":{"protocol":"FixedRatio",
                  "rules":[{"deploymentId":"deployment-1","trafficPercentage":100}]}}
                """);
        var deployment = resource("project/applications/app/agentdeployments/deploy","project/applications/app","""
                {"deploymentId":"deployment-1","state":"Running","protocols":[{"protocol":"Responses"}],
                 "agents":[{"agentName":"support","agentVersion":"2"}]}
                """);
        var route = client.legacyFoundryRouteResource(agent,List.of(app),List.of(deployment),Map.of());
        assertEquals("READY",route.properties().path("status").asText());
        assertEquals("2",route.properties().path("routedVersions").get(0).asText());
        var unrelated = resource("other-project/agents/support","other-project","{}");
        assertEquals("NO_ACTIVE_DEPLOYMENT",client.legacyFoundryRouteResource(unrelated,List.of(app),List.of(deployment),Map.of())
                .properties().path("status").asText());
        var stopped = resource(deployment.id(),deployment.parentId(),deployment.properties().toString().replace("Running","Stopped"));
        assertEquals("NO_ACTIVE_DEPLOYMENT",client.legacyFoundryRouteResource(agent,List.of(app),List.of(stopped),Map.of())
                .properties().path("status").asText());
    }
    @Test void legacyFailureAndTransitionalStatesCannotEstablishAbsence() throws Exception {
        var agent = resource("project/agents/support","project","{}");
        var app = resource("project/applications/app","project","{\"agents\":[{\"agentName\":\"support\"}]}");
        var starting = resource("deployment","project/applications/app","{\"state\":\"Starting\",\"agents\":[{\"agentName\":\"support\",\"agentVersion\":\"2\"}]}");
        assertEquals("AMBIGUOUS_ROUTE_STATE", client.legacyFoundryRouteResource(agent,List.of(app),List.of(starting),Map.of())
                .properties().path("deploymentEvidenceReason").asText());
        assertEquals("PERMISSION_DENIED",client.legacyFoundryRouteResource(agent,List.of(),List.of(),Map.of(
                "AZURE_FOUNDRY_AGENT_APPLICATIONS",new AzureApiFailure("AZURE_FORBIDDEN","Permission missing",false,403)))
                .properties().path("deploymentEvidenceReason").asText());
    }
    @Test void providerDeploymentsAreSupportingResourcesAndPermissionsAreExact() {
        assertEquals("AZURE_FOUNDRY_AGENT_DEPLOYMENTS",client.family("Microsoft.CognitiveServices/accounts/projects/applications/agentDeployments"));
        var matrix = new AzurePolicyPermissionMatrix();
        assertTrue(matrix.family("AZURE_FOUNDRY_AGENT_ROUTES").dataActions().contains("Microsoft.CognitiveServices/accounts/AIServices/agents/read"));
        assertTrue(matrix.roleTemplate().dataActions().contains("Microsoft.CognitiveServices/accounts/AIServices/agents/read"));
        assertEquals(List.of("Microsoft.CognitiveServices/accounts/projects/applications/agentdeployments/read"),
                matrix.family("AZURE_FOUNDRY_AGENT_DEPLOYMENTS").actions());
    }
}
