package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import java.util.List;
import org.junit.jupiter.api.Test;

class AiSecurityFieldContractTest {
    @Test
    void exposesOnlyExplicitResponseMetadataAndNeverDigestOrContent() {
        Map<String, Object> safe = AiSecurityFieldContract.responseSafe(Map.of(
                "status", "ACTIVE", "promptDigest", "never-public", "unknown", "not-contracted",
                "messages", "do not retain"));

        assertEquals(Map.of("status", "ACTIVE"), safe);
        assertFalse(AiSecurityFieldContract.allows("promptDigest", AiSecurityFieldContract.Tier.RESPONSE_ALLOWED));
        assertFalse(AiSecurityFieldContract.allows("unknown", AiSecurityFieldContract.Tier.STORAGE_ALLOWED));
        assertFalse(AiSecurityFieldContract.allows("messages", AiSecurityFieldContract.Tier.STORAGE_ALLOWED));
    }

    @Test
    void storesDigestButDoesNotMakeItFilterable() {
        assertTrue(AiSecurityFieldContract.allows("promptDigest", AiSecurityFieldContract.Tier.STORAGE_ALLOWED));
        assertFalse(AiSecurityFieldContract.allows("promptDigest", AiSecurityFieldContract.Tier.FILTER_ALLOWED));
    }

    @Test
    void permitsReviewedContentPostureFieldsWithoutPermittingRawContent() {
        assertTrue(AiSecurityFieldContract.allows(
                "publicContentAccess", AiSecurityFieldContract.Tier.RESPONSE_ALLOWED));
        assertTrue(AiSecurityFieldContract.allows(
                "contentFilterCount", AiSecurityFieldContract.Tier.RESPONSE_ALLOWED));
        assertFalse(AiSecurityFieldContract.allows(
                "content", AiSecurityFieldContract.Tier.STORAGE_ALLOWED));
    }

    @Test
    void retainsReconciledProviderFieldsOnlyForStorage() {
        for (String field : java.util.List.of("modelDataS3Uri", "trainingDataS3Uri",
                "validationDataS3Uris", "principalId", "providerNativeId")) {
            assertTrue(AiSecurityFieldContract.allows(field, AiSecurityFieldContract.Tier.STORAGE_ALLOWED));
            assertFalse(AiSecurityFieldContract.allows(field, AiSecurityFieldContract.Tier.RESPONSE_ALLOWED));
            assertFalse(AiSecurityFieldContract.allows(field, AiSecurityFieldContract.Tier.FILTER_ALLOWED));
        }
    }

    @Test
    void preservesReviewedCollectorMetadataIncludingNestedGuardrailFields() {
        Map<String, Object> safe = AiSecurityFieldContract.responseSafe(Map.of(
                "endpointHost", "gateway.example.test",
                "sourceType", "S3",
                "contentFilters", List.of(Map.of(
                        "type", "HATE",
                        "inputStrength", "HIGH",
                        "outputStrength", "MEDIUM",
                        "inputEnabled", true,
                        "outputEnabled", true)),
                "deniedTopics", List.of(Map.of(
                        "name", "Investment advice",
                        "inputAction", "BLOCK",
                        "outputAction", "BLOCK"))));

        assertEquals("gateway.example.test", safe.get("endpointHost"));
        assertEquals("S3", safe.get("sourceType"));
        assertEquals("HATE", nestedValue(safe, "contentFilters", "type"));
        assertEquals("HIGH", nestedValue(safe, "contentFilters", "inputStrength"));
        assertEquals("Investment advice", nestedValue(safe, "deniedTopics", "name"));
        assertEquals("BLOCK", nestedValue(safe, "deniedTopics", "inputAction"));
    }

    @Test
    void preservesMetadataFieldsReadDirectlyByInventoryAndAssetPages() {
        Map<String, Object> expected = Map.of(
                "endpointHost", "gateway.example.test",
                "endpointExposure", "PRIVATE",
                "configuredAuthType", "MANAGED_IDENTITY",
                "inboundAuthType", "OAUTH",
                "status", "READY",
                "lastSynchronizedAt", "2026-09-17T00:00:00Z",
                "aclSupport", "SUPPORTED",
                "retrievalMode", "HYBRID",
                "storeType", "AZURE_STORAGE",
                "backingStore", "legacy-store");

        assertEquals(expected, AiSecurityFieldContract.responseSafe(expected));
    }

    @Test
    void preservesDynamicTagsWithoutAdmittingSensitiveTagNames() {
        Map<String, Object> safe = AiSecurityFieldContract.responseSafe(Map.of(
                "tags", Map.of(
                        "team", "AI Platform",
                        "environment", "production",
                        "api-token", "must-not-be-returned")));

        assertEquals(Map.of("team", "AI Platform", "environment", "production"), safe.get("tags"));
    }

    @SuppressWarnings("unchecked")
    private static Object nestedValue(Map<String, Object> value, String collection, String field) {
        return ((List<Map<String, Object>>) value.get(collection)).get(0).get(field);
    }
}
