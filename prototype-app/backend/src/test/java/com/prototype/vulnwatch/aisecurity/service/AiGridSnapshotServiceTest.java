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
}
