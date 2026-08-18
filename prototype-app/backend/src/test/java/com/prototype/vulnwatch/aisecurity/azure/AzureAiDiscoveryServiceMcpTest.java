package com.prototype.vulnwatch.aisecurity.azure;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import org.junit.jupiter.api.Test;

class AzureAiDiscoveryServiceMcpTest {

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
