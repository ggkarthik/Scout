package com.prototype.vulnwatch.aisecurity.aws;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

class AwsAgentCoreGatewaySanitizationTest {

    @Test
    void retainsOnlyHttpsAuthorityForAConfiguredEndpoint() {
        assertEquals("mcp.example.com:8443", AwsBedrockDiscoveryService.httpsAuthority(
                "https://MCP.example.com:8443/private/path?token=do-not-store#fragment"));
    }

    @Test
    void rejectsCredentialBearingAndNonHttpsEndpoints() {
        assertNull(AwsBedrockDiscoveryService.httpsAuthority("http://mcp.example.com"));
        assertNull(AwsBedrockDiscoveryService.httpsAuthority("https://user:secret@mcp.example.com"));
    }
}
