package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AiSecurityMetadataSanitizerTest {
    private final AiSecurityMetadataSanitizer sanitizer = new AiSecurityMetadataSanitizer();

    @Test
    void enforcesTheRegisteredAgentSchemaAndDropsFreeFormContent() {
        var result = sanitizer.sanitize("AWS", "AWS_BEDROCK_AGENT", Map.of(
                "status", "ACTIVE",
                "description", "customer secret in a free-form field",
                "blockedInputMessaging", "confidential guardrail response",
                "unexpectedMetadata", "not in the schema",
                "promptText", "do not retain",
                "longValue", "x".repeat(AiSecurityMetadataSanitizer.MAX_STRING_LENGTH + 1)));

        assertEquals("ACTIVE", result.attributes().get("status"));
        assertTrue(result.rejectedFieldNames().containsAll(List.of(
                "description", "blockedInputMessaging", "unexpectedMetadata", "promptText", "longValue")));
    }

    @Test
    void dropsAllAttributesForAnUnregisteredNativeKind() {
        var result = sanitizer.sanitize("AWS", "AWS_FUTURE_SECRET_SERVICE", Map.of("status", "ACTIVE"));
        var unknown = sanitizer.sanitize("OTHER", "FUTURE_KIND", Map.of("status", "ACTIVE"));
        assertTrue(unknown.attributes().isEmpty());
        assertFalse(unknown.rejectedFieldNames().isEmpty());
        assertTrue(result.attributes().isEmpty());
    }

    @Test
    void permitsOnlySafeAzureDataStorePostureMetadata() {
        var result = sanitizer.sanitize("AZURE", "AZURE_STORAGE_ACCOUNTS", Map.of(
                "storeType", "AZURE_STORAGE", "connectionString", "AccountKey=secret", "headers", Map.of("x-api-key", "secret")));
        assertEquals("AZURE_STORAGE", result.attributes().get("storeType"));
        assertTrue(result.rejectedFieldNames().contains("connectionString"));
        assertTrue(result.rejectedFieldNames().contains("headers"));
    }

    @Test
    void retainsInternalDigestsButRejectsUncontractedNestedContent() {
        var result = sanitizer.sanitize("AZURE", "AZURE_FOUNDRY_PROMPT", Map.of(
                "promptDigest", "hmac-value",
                "digestAlgorithm", "HMAC-SHA-256",
                "digestKeyVersion", "v7",
                "evidence", Map.of("sourceApi", "Foundry", "promptBody", "never retain")));

        assertEquals("hmac-value", result.attributes().get("promptDigest"));
        assertEquals("HMAC-SHA-256", result.attributes().get("digestAlgorithm"));
        assertEquals(Map.of("sourceApi", "Foundry"), result.attributes().get("evidence"));
        assertTrue(result.rejectedFieldNames().contains("evidence.promptBody"));
    }

    @Test
    void retainsReviewedNestedGuardrailPostureMetadata() {
        var result = sanitizer.sanitize("AWS", "AWS_BEDROCK_GUARDRAIL", Map.of(
                "contentFilters", List.of(Map.of(
                        "type", "HATE", "inputStrength", "HIGH", "outputStrength", "MEDIUM")),
                "contextualGroundingFilters", List.of(Map.of(
                        "type", "GROUNDING", "threshold", 0.85, "action", "BLOCK"))));

        @SuppressWarnings("unchecked")
        var filters = (List<Map<String, Object>>) result.attributes().get("contentFilters");
        assertEquals("HATE", filters.get(0).get("type"));
        assertEquals("HIGH", filters.get(0).get("inputStrength"));
        @SuppressWarnings("unchecked")
        var grounding = (List<Map<String, Object>>) result.attributes().get("contextualGroundingFilters");
        assertEquals(0.85, grounding.get(0).get("threshold"));
        assertEquals("BLOCK", grounding.get(0).get("action"));
    }

    @Test
    void rejectsReviewedNestedNamesWhenTheyAppearAtTheWrongSchemaPath() {
        var result = sanitizer.sanitize("AWS", "AWS_BEDROCK_GUARDRAIL", Map.of(
                "name", "unexpected top-level value",
                "contentFilters", List.of(Map.of(
                        "type", "HATE", "name", "unexpected nested value", "source", "unexpected"))));

        assertFalse(result.attributes().containsKey("name"));
        @SuppressWarnings("unchecked")
        var filters = (List<Map<String, Object>>) result.attributes().get("contentFilters");
        assertEquals(Map.of("type", "HATE"), filters.get(0));
        assertTrue(result.rejectedFieldNames().contains("name"));
        assertTrue(result.rejectedFieldNames().contains("contentFilters[0].name"));
        assertTrue(result.rejectedFieldNames().contains("contentFilters[0].source"));
    }

    @Test
    void retainsPostureTagsAndRejectsSensitiveTagNames() {
        var result = sanitizer.sanitize("AWS", "AWS_BEDROCK_AGENT", Map.of(
                "tags", Map.of(
                        "team", "AI Platform Team",
                        "environment", "production",
                        "credential", "must-not-be-retained")));

        assertEquals(Map.of("team", "AI Platform Team", "environment", "production"),
                result.attributes().get("tags"));
        assertTrue(result.rejectedFieldNames().contains("tags.credential"));
    }
}
