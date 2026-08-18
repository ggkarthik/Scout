package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

class AiGridSnapshotServiceTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final AiGridSnapshotService service = new AiGridSnapshotService(
            org.mockito.Mockito.mock(NamedParameterJdbcTemplate.class), mapper);

    @Test
    void standardProfileRecursivelyRemovesSecretsAndRawPromptContent() throws Exception {
        var source = mapper.readTree("""
                {
                  "guardrailMinimumStrength": "MEDIUM",
                  "clientSecret": "do-not-store",
                  "nested": {
                    "access_token": "do-not-store",
                    "rawPrompt": "private customer prompt",
                    "contentFilters": {"violence": "HIGH"}
                  },
                  "items": [{"password": "do-not-store", "enabled": true}]
                }
                """);

        var safe = service.redactAttributes(source);

        assertEquals("MEDIUM", safe.path("guardrailMinimumStrength").asText());
        assertTrue(safe.path("nested").path("contentFilters").has("violence"));
        assertTrue(safe.path("items").get(0).path("enabled").asBoolean());
        assertFalse(safe.has("clientSecret"));
        assertFalse(safe.path("nested").has("access_token"));
        assertFalse(safe.path("nested").has("rawPrompt"));
        assertFalse(safe.path("items").get(0).has("password"));
    }

    @Test
    void externalEndpointWithoutProviderConfirmedPublicReachabilityDoesNotBecomePolicyFact() throws Exception {
        var attributes = mapper.readTree("""
                {
                  "endpointExposure": "EXTERNAL_ENDPOINT",
                  "configuredAuthType": "NONE"
                }
                """);

        var facts = service.normalize(attributes, "MCP_SERVER", null, null);

        assertFalse(facts.containsKey("mcp.endpoint_exposure"));
        assertEquals("NONE", facts.get("mcp.configured_auth_type").asText());
    }

    @Test
    void providerConfirmedPublicReachabilityBecomesPolicyFact() throws Exception {
        var attributes = mapper.readTree("""
                {
                  "endpointExposure": "PUBLIC_NETWORK_REACHABLE",
                  "configuredAuthType": "NONE"
                }
                """);

        var facts = service.normalize(attributes, "MCP_SERVER", null, null);

        assertEquals("PUBLIC_NETWORK_REACHABLE", facts.get("mcp.endpoint_exposure").asText());
    }

    @Test
    void unknownSensitivityRemainsUnknownAndDoesNotBecomeConfirmedSensitive() throws Exception {
        var facts = service.normalize(mapper.createObjectNode(), "DATA_STORE", "UNKNOWN", "AZURE_PURVIEW");

        assertEquals("UNKNOWN", facts.get("data.source_sensitivity").asText());
        assertFalse(facts.containsKey("data.sensitivity_confirmed"));
    }
}
