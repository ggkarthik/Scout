package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
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
}
