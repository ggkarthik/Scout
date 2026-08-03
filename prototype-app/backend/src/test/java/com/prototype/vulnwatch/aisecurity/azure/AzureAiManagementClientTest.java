package com.prototype.vulnwatch.aisecurity.azure;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.aisecurity.policy.AiSecurityPolicyRegistry;
import java.net.URI;
import java.net.http.HttpHeaders;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AzureAiManagementClientTest {

    private final AzureAiManagementClient client = new AzureAiManagementClient(
            new ObjectMapper(),
            new AzurePolicyPermissionMatrix(new AiSecurityPolicyRegistry()));

    @Test
    void acceptsOnlyThePinnedAzureManagementHost() {
        assertDoesNotThrow(() -> client.validateManagementUri(
                URI.create("https://management.azure.com/subscriptions/example/resources")));

        var exception = assertThrows(
                AzureAiManagementClient.AzureApiException.class,
                () -> client.validateManagementUri(
                        URI.create("https://management.azure.com.attacker.example/steal")));
        assertEquals("INVALID_CONFIGURATION", exception.failure().code());
    }

    @Test
    void rejectsDowngradesAndEmbeddedCredentials() {
        assertThrows(
                AzureAiManagementClient.AzureApiException.class,
                () -> client.validateManagementUri(
                        URI.create("http://management.azure.com/subscriptions/example")));
        assertThrows(
                AzureAiManagementClient.AzureApiException.class,
                () -> client.validateManagementUri(
                        URI.create("https://user@management.azure.com/subscriptions/example")));
    }

    @Test
    void classifiesSubscriptionRoleAssignmentsAsGlobalRbac() {
        assertEquals(
                "AZURE_RBAC_GLOBAL",
                client.family("Microsoft.Authorization/roleAssignments"));
    }

    @Test
    void classifiesRaiPoliciesAsFirstClassDiscoveryResources() {
        assertEquals(
                "AZURE_RAI_POLICIES",
                client.family("Microsoft.CognitiveServices/accounts/raiPolicies"));
    }

    @Test
    void honorsAndBoundsAzureRetryHeaders() {
        HttpHeaders milliseconds = HttpHeaders.of(
                Map.of("x-ms-retry-after-ms", List.of("1200")), (name, value) -> true);
        HttpHeaders excessive = HttpHeaders.of(
                Map.of("Retry-After", List.of("600")), (name, value) -> true);

        assertEquals(Duration.ofMillis(1200), client.retryDelay(milliseconds, 1));
        assertEquals(Duration.ofSeconds(5), client.retryDelay(excessive, 1));
    }

    @Test
    void classifiesMlDeploymentsAndPipelineJobs() {
        assertEquals(
                "AZURE_ML_DEPLOYMENTS",
                client.family("Microsoft.MachineLearningServices/workspaces/onlineEndpoints/deployments"));
        var properties = new ObjectMapper().createObjectNode().put("jobType", "Pipeline");
        var resource = new AzureAiManagementClient.AzureResource(
                "/subscriptions/sub/jobs/job-1",
                "/subscriptions/sub/jobs/job-1",
                "job-1",
                "Microsoft.MachineLearningServices/workspaces/jobs",
                null,
                "eastus",
                "sub",
                "rg",
                new ObjectMapper().createObjectNode(),
                properties,
                new ObjectMapper().createObjectNode(),
                Map.of(),
                "/subscriptions/sub/workspaces/ws-1");

        assertTrue(client.isPipelineJob(resource));
    }
}
