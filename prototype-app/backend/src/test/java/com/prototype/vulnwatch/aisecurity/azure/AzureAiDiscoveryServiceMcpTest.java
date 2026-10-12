package com.prototype.vulnwatch.aisecurity.azure;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import org.junit.jupiter.api.Test;

class AzureAiDiscoveryServiceMcpTest {

    @Test
    void oneUnsupportedProjectDoesNotDiscardAgentsFromAnotherProject() {
        var mapper = new ObjectMapper();
        var service = new AzureAiDiscoveryService(null,null,null,null,null,null,
                new AzurePolicyPermissionMatrix(),org.mockito.Mockito.mock(AiSecurityAzureKillSwitchService.class),
                null,null,null,null,null,mapper,null,null,null,true,true,true,false,false,false,10000);
        var agent = new AzureAiManagementClient.AzureResource("project/agents/test","project/agents/test","test",
                "Microsoft.Foundry/projects/agents","FoundryPromptAgent","eastus","sub","rg",
                mapper.createObjectNode(),mapper.createObjectNode(),mapper.createObjectNode(),java.util.Map.of(),null);
        var snapshot = new AzureAiManagementClient.DiscoverySnapshot(
                java.util.Map.of("AZURE_FOUNDRY_AGENTS",List.of(agent)),
                java.util.Map.of("AZURE_FOUNDRY_AGENTS",new AzureAiManagementClient.AzureApiFailure("NOT_FOUND","Other project unavailable",false,404)));
        Object payload = org.springframework.test.util.ReflectionTestUtils.invokeMethod(service,"payload",
                "AZURE_FOUNDRY_AGENTS","eastus",snapshot,java.util.Map.of(),null,null);
        assertEquals(com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ScopeStatus.PARTIAL,
                org.springframework.test.util.ReflectionTestUtils.invokeMethod(payload,"status"));
        List<?> artifacts = org.springframework.test.util.ReflectionTestUtils.invokeMethod(payload,"artifacts");
        assertEquals(1L, artifacts.stream()
                .filter(com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ArtifactObservation.class::isInstance)
                .map(com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ArtifactObservation.class::cast)
                .filter(artifact -> "AZURE_FOUNDRY_AGENTS".equals(artifact.nativeKind()))
                .count());
    }

    @Test
    void keepsOnlyAnInertHttpsAuthorityForMcpEndpoints() {
        assertEquals("https://mcp.example.com:8443",
                AzureAiDiscoveryService.normalizedMcpEndpoint(
                        "https://MCP.example.com:8443/customer/path?token=never-store#fragment"));
    }

    @Test
    void rejectsMcpEndpointsThatCouldCarryCredentialsOrUseNonHttpsProtocols() {
        assertNull(AzureAiDiscoveryService.normalizedMcpEndpoint("http://mcp.example.com"));
        assertNull(AzureAiDiscoveryService.normalizedMcpEndpoint("https://user:secret@mcp.example.com"));
        assertNull(AzureAiDiscoveryService.normalizedMcpEndpoint("not a URL"));
    }

    @Test
    void resolvesOnlyStableArmStorageReferencesFromKnowledgeDefinitions() throws Exception {
        var definition = new ObjectMapper().readTree("""
                {"resourceId":"/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/docs",
                 "endpoint":"https://example.invalid/secret", "connectionString":"AccountKey=secret"}
                """);
        assertEquals(List.of("/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/docs"),
                AzureAiDiscoveryService.stableAzureResourceIds(definition));
    }

    @Test
    void resolvesOnlyManagedIdentityResourceIdConnectionStrings() throws Exception {
        var definition = new ObjectMapper().readTree("""
                {"connectionString":"ResourceId=/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/docs;"}
                """);
        assertEquals(List.of("/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/docs"),
                AzureAiDiscoveryService.stableAzureResourceIds(definition));
    }

    @Test
    void treatsMissingFoundryMcpAuthenticationAsUnknownRatherThanNone() throws Exception {
        var tool = new ObjectMapper().readTree("{\"type\":\"mcp\",\"server_url\":\"https://mcp.example.com\"}");
        assertEquals("UNKNOWN", AzureAiDiscoveryService.configuredMcpAuthType(tool));
    }
}
