package com.prototype.vulnwatch.aisecurity.azure;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenCredential;
import com.azure.core.credential.TokenRequestContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * Reads whatever classification results already exist in the customer's Microsoft Purview
 * account for a given Storage Account — a metadata search against Purview's Data Map, never a
 * scan Scout triggers itself and never a read of blob content. Purview account name is optional
 * connector config; when it isn't set, PII lookups are simply reported as not scanned.
 *
 * <p>Targets the Purview Data Map "Discovery - Query" API (POST /datamap/api/search/query,
 * api-version 2023-09-01). This should be verified against a live Purview account before the
 * {@code app.ai-security.azure.purview-pii.enabled} flag (default off) is turned on.
 */
@Component
public class AzurePurviewClassificationClient {

    private static final String PURVIEW_SCOPE = "https://purview.azure.com/.default";
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(15);

    private final HttpClient http;
    private final ObjectMapper objectMapper;

    public AzurePurviewClassificationClient(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    public PiiLookupResult lookup(TokenCredential credential, String purviewAccountName, String storageAccountName) {
        if (purviewAccountName == null || purviewAccountName.isBlank()) {
            return notScanned();
        }
        try {
            URI uri = URI.create("https://" + purviewAccountName.trim().toLowerCase(Locale.ROOT)
                    + ".purview.azure.com/datamap/api/search/query?api-version=2023-09-01");
            validatePurviewUri(uri);
            String body = objectMapper.writeValueAsString(Map.of("keywords", storageAccountName, "limit", 25));
            HttpRequest request = HttpRequest.newBuilder(uri)
                    .timeout(REQUEST_TIMEOUT)
                    .header("Authorization", "Bearer " + bearerToken(credential))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                    .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 404) {
                return notScanned();
            }
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                return lookupFailed();
            }
            return parseResults(objectMapper.readTree(response.body()));
        } catch (Exception ex) {
            return lookupFailed();
        }
    }

    PiiLookupResult parseResults(JsonNode root) {
        Set<String> infoTypes = new LinkedHashSet<>();
        int classifiedEntityCount = 0;
        JsonNode values = root.path("value");
        if (values.isArray()) {
            for (JsonNode entity : values) {
                JsonNode classifications = entity.path("classifications");
                if (classifications.isArray() && !classifications.isEmpty()) {
                    classifiedEntityCount++;
                    for (JsonNode classification : classifications) {
                        String typeName = classification.path("typeName").asText(null);
                        if (typeName != null && !typeName.isBlank()) {
                            infoTypes.add(typeName);
                        }
                    }
                }
            }
        }
        if (classifiedEntityCount == 0) {
            return scannedClean();
        }
        return new PiiLookupResult("SCANNED_PII_FOUND", "AZURE_PURVIEW", List.copyOf(infoTypes),
                classifiedEntityCount, Instant.now());
    }

    void validatePurviewUri(URI uri) {
        String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT);
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getUserInfo() != null
                || !host.endsWith(".purview.azure.com")) {
            throw new IllegalArgumentException("Azure Purview endpoint is not allowed");
        }
    }

    private String bearerToken(TokenCredential credential) {
        AccessToken token = credential.getToken(new TokenRequestContext().addScopes(PURVIEW_SCOPE))
                .block(Duration.ofSeconds(30));
        if (token == null || token.getToken() == null || token.getToken().isBlank()) {
            throw new IllegalStateException("Unable to acquire Azure Purview token");
        }
        return token.getToken();
    }

    private PiiLookupResult scannedClean() {
        return new PiiLookupResult("SCANNED_CLEAN", "AZURE_PURVIEW", List.of(), 0, Instant.now());
    }

    private PiiLookupResult notScanned() {
        return new PiiLookupResult("NOT_SCANNED", "AZURE_PURVIEW", List.of(), 0, null);
    }

    private PiiLookupResult lookupFailed() {
        return new PiiLookupResult("LOOKUP_FAILED", "AZURE_PURVIEW", List.of(), 0, null);
    }

    public record PiiLookupResult(
            String status,
            String source,
            List<String> infoTypes,
            int findingCount,
            Instant lastScannedAt
    ) {
    }
}
