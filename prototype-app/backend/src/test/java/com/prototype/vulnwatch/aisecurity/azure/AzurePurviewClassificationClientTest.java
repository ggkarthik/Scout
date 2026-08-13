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
                    { "classifications": [ { "typeName": "MICROSOFT.PERSONAL.EMAIL" } ] },
                    { "classifications": [ { "typeName": "MICROSOFT.PERSONAL.EMAIL" }, { "typeName": "MICROSOFT.PERSONAL.NAME" } ] },
                    { "classifications": [] }
                  ]
                }
                """);
        var result = client.parseResults(root);
        assertEquals("SCANNED_PII_FOUND", result.status());
        assertEquals(2, result.findingCount());
        assertTrue(result.infoTypes().containsAll(
                java.util.List.of("MICROSOFT.PERSONAL.EMAIL", "MICROSOFT.PERSONAL.NAME")));
    }

    @Test
    void reportsCleanWhenNoEntityHasClassifications() throws Exception {
        var root = objectMapper.readTree("{ \"value\": [] }");
        var result = client.parseResults(root);
        assertEquals("SCANNED_CLEAN", result.status());
        assertEquals(0, result.findingCount());
    }
}
