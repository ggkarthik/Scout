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
}
