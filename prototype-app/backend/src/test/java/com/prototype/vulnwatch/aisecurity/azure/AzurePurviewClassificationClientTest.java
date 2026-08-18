package com.prototype.vulnwatch.aisecurity.azure;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.azure.core.credential.TokenCredential;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import org.junit.jupiter.api.Test;

class AzurePurviewClassificationClientTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final AzurePurviewClassificationClient client = new AzurePurviewClassificationClient(objectMapper);

    @Test
    void acceptsOnlyPinnedPurviewHosts() {
        assertDoesNotThrow(() -> client.validatePurviewUri(
                URI.create("https://contoso.purview.azure.com/datamap/api/search/query")));

        assertThrows(IllegalArgumentException.class, () -> client.validatePurviewUri(
                URI.create("https://contoso.purview.azure.com.attacker.example/steal")));
    }

    @Test
    void rejectsDowngradesAndEmbeddedCredentials() {
        assertThrows(IllegalArgumentException.class, () -> client.validatePurviewUri(
                URI.create("http://contoso.purview.azure.com/datamap/api/search/query")));
        assertThrows(IllegalArgumentException.class, () -> client.validatePurviewUri(
                URI.create("https://user@contoso.purview.azure.com/datamap/api/search/query")));
    }

    @Test
    void reportsNotScannedWhenNoPurviewAccountIsConfigured() {
        TokenCredential credential = context -> {
            throw new AssertionError("no token should be requested when Purview isn't configured");
        };
        var result = client.lookup(credential, null, "mystorageaccount");
        assertEquals("NOT_SCANNED", result.status());
        assertEquals(0, result.findingCount());
    }

    @Test
    void parsesClassifiedEntitiesIntoDistinctInfoTypes() throws Exception {
        var root = objectMapper.readTree("""
                {
                  "value": [
                    { "qualifiedName": "https://mystorageaccount.blob.core.windows.net/a/one.csv",
                      "classification": ["MICROSOFT.PERSONAL.EMAIL"] },
                    { "qualifiedName": "https://mystorageaccount.dfs.core.windows.net/a/two.csv",
                      "classification": ["MICROSOFT.PERSONAL.EMAIL", "MICROSOFT.PERSONAL.NAME"] },
                    { "qualifiedName": "https://otheraccount.blob.core.windows.net/a/three.csv",
                      "classification": ["MICROSOFT.PERSONAL.PASSPORT_NUMBER"] }
                  ]
                }
                """);
        var result = client.parseResults(root, "mystorageaccount");
        assertEquals("SCANNED_PII_FOUND", result.status());
        assertEquals(2, result.findingCount());
        assertTrue(result.infoTypes().containsAll(
                java.util.List.of("MICROSOFT.PERSONAL.EMAIL", "MICROSOFT.PERSONAL.NAME")));
    }

    @Test
    void reportsUnknownWhenSearchHasNoAuthoritativeClassificationEvidence() throws Exception {
        var root = objectMapper.readTree("{ \"value\": [] }");
        var result = client.parseResults(root, "mystorageaccount");
        assertEquals("UNKNOWN", result.status());
        assertEquals(0, result.findingCount());
    }

    @Test
    void ignoresClassificationsThatAreNotBoundToTheRequestedStorageAccount() throws Exception {
        var root = objectMapper.readTree("""
                {"value":[{"qualifiedName":"https://other.blob.core.windows.net/a.csv",
                            "classification":["MICROSOFT.PERSONAL.EMAIL"]}]}
                """);
        assertEquals("UNKNOWN", client.parseResults(root, "mystorageaccount").status());
    }

    @Test
    void acceptsAnExactArmQualifiedStorageAccountIdentity() throws Exception {
        var root = objectMapper.readTree("""
                {"value":[{"qualifiedName":"/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/mystorageaccount",
                            "classification":["MICROSOFT.PERSONAL.EMAIL"]}]}
                """);
        assertEquals("SCANNED_PII_FOUND", client.parseResults(root, "mystorageaccount").status());
    }
}
