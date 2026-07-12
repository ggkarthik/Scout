package com.prototype.vulnwatch.client;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenCredential;
import com.azure.core.credential.TokenRequestContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class AzureDiscoveryClient {

    private static final Logger LOG = LoggerFactory.getLogger(AzureDiscoveryClient.class);
    private static final String MANAGEMENT_SCOPE = "https://management.azure.com/.default";
    private static final String API_VERSION = "2021-04-01";

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public AzureDiscoveryClient(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15))
                .build();
    }

    /** Test connectivity to a single Azure subscription using the shared credential. */
    public AzureConnectivityResult testConnectivity(TokenCredential credential, String subscriptionId) {
        try {
            JsonNode response = getJson(credential,
                    "https://management.azure.com/subscriptions/" + encode(subscriptionId) + "?api-version=2020-01-01");
            String displayName = textOrNull(response.path("displayName"));
            return new AzureConnectivityResult(true, subscriptionId, hasText(displayName) ? displayName : subscriptionId, null);
        } catch (Exception e) {
            LOG.debug("Azure subscription {} failed connectivity test: {}", subscriptionId, e.getMessage());
            return new AzureConnectivityResult(false, subscriptionId, null, e.getMessage());
        }
    }

    /** Fetch all resources for a single subscription, filtered by region if regions is non-empty. */
    public AzureResourceFetchResult fetchResources(TokenCredential credential, String subscriptionId, List<String> regions) {
        List<AzureResourceRecord> records = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        String nextUrl = "https://management.azure.com/subscriptions/" + encode(subscriptionId) + "/resources?api-version=" + API_VERSION;
        String error = null;

        while (nextUrl != null) {
            try {
                JsonNode response = getJson(credential, nextUrl);
                JsonNode values = response.path("value");
                if (values.isArray()) {
                    for (JsonNode value : values) {
                        AzureResourceRecord record = toRecord(subscriptionId, value);
                        if (record.resourceId() == null || !seen.add(record.resourceId())) {
                            continue;
                        }
                        if (matchesRegion(record.location(), regions)) {
                            records.add(record);
                        }
                    }
                }
                nextUrl = textOrNull(response.path("nextLink"));
            } catch (Exception e) {
                LOG.warn("Azure resource fetch failed for subscription {}: {}", subscriptionId, e.getMessage());
                error = e.getMessage();
                nextUrl = null;
            }
        }

        return new AzureResourceFetchResult(records, error);
    }

    private boolean matchesRegion(String location, List<String> regions) {
        if (regions == null || regions.isEmpty() || !hasText(location)) {
            return true;
        }
        return regions.stream().anyMatch(region -> region != null && region.equalsIgnoreCase(location.trim()));
    }

    private AzureResourceRecord toRecord(String subscriptionId, JsonNode value) {
        String resourceId = textOrNull(value.path("id"));
        String name = textOrNull(value.path("name"));
        String resourceType = textOrNull(value.path("type"));
        String location = textOrNull(value.path("location"));
        String kind = textOrNull(value.path("kind"));
        String provisioningState = textOrNull(value.path("properties").path("provisioningState"));
        String resourceGroup = extractResourceGroup(resourceId);
        Map<String, String> tags = new LinkedHashMap<>();
        JsonNode tagsNode = value.path("tags");
        if (tagsNode.isObject()) {
            tagsNode.fields().forEachRemaining(entry -> tags.put(entry.getKey(), entry.getValue().asText()));
        }
        return new AzureResourceRecord(
                subscriptionId,
                resourceId,
                hasText(name) ? name : fallbackName(resourceId),
                resourceType,
                resourceGroup,
                location,
                kind,
                provisioningState,
                tags
        );
    }

    private JsonNode getJson(TokenCredential credential, String url) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Authorization", "Bearer " + bearerToken(credential))
                .header("Content-Type", "application/json")
                .GET()
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IllegalStateException("Azure management API returned " + response.statusCode() + ": " + abbreviate(response.body()));
        }
        return objectMapper.readTree(response.body());
    }

    private String bearerToken(TokenCredential credential) {
        AccessToken token = credential.getToken(new TokenRequestContext().addScopes(MANAGEMENT_SCOPE))
                .block(Duration.ofSeconds(30));
        if (token == null || token.getToken() == null || token.getToken().isBlank()) {
            throw new IllegalStateException("Unable to acquire Azure management API token");
        }
        return token.getToken();
    }

    private String extractResourceGroup(String resourceId) {
        if (!hasText(resourceId)) {
            return null;
        }
        String marker = "/resourceGroups/";
        int start = resourceId.indexOf(marker);
        if (start < 0) {
            return null;
        }
        String remainder = resourceId.substring(start + marker.length());
        int end = remainder.indexOf('/');
        return end < 0 ? remainder : remainder.substring(0, end);
    }

    private String fallbackName(String resourceId) {
        if (!hasText(resourceId)) {
            return "unknown";
        }
        int slash = resourceId.lastIndexOf('/');
        return slash >= 0 && slash + 1 < resourceId.length() ? resourceId.substring(slash + 1) : resourceId;
    }

    private String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private String abbreviate(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.length() > 240 ? trimmed.substring(0, 240) + "..." : trimmed;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private String textOrNull(JsonNode node) {
        return node == null || node.isMissingNode() || node.isNull() ? null : node.asText(null);
    }

    public record AzureResourceRecord(
            String subscriptionId,
            String resourceId,
            String name,
            String resourceType,
            String resourceGroup,
            String location,
            String kind,
            String provisioningState,
            Map<String, String> tags
    ) {}

    public record AzureConnectivityResult(
            boolean success,
            String subscriptionId,
            String subscriptionName,
            String errorMessage
    ) {}

    public record AzureResourceFetchResult(
            List<AzureResourceRecord> records,
            String error
    ) {}
}
