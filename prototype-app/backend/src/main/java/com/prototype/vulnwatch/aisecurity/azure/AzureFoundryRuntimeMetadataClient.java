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
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Reads Foundry execution metadata only; response content is never represented in this client. */
@Component
public class AzureFoundryRuntimeMetadataClient {
    private final ObjectMapper json; private final int maxPages; private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15)).followRedirects(HttpClient.Redirect.NEVER).build();
    public AzureFoundryRuntimeMetadataClient(ObjectMapper json,
                                             @Value("${app.ai-security.runtime.max-api-calls-per-run:100}") int maxPages) { this.json = json; this.maxPages = Math.max(1, maxPages); }
    public CollectionResult list(TokenCredential credential, String endpoint, Instant after) {
        URI base = URI.create(endpoint.endsWith("/") ? endpoint : endpoint + "/"); validate(base);
        List<Execution> result = new ArrayList<>(); Set<URI> visited = new LinkedHashSet<>();
        URI next = base.resolve("openai/v1/responses?limit=100&order=desc");
        for (int page = 0; next != null; page++) {
            if (page >= maxPages) return new CollectionResult(result, "PARTIAL", "API_CALL_BUDGET_EXHAUSTED");
            if (!visited.add(next)) return new CollectionResult(result, "PARTIAL", "PAGINATION_CYCLE_DETECTED");
            validatePage(next, base);
            JsonNode body;
            try {
                body = get(credential, next);
            } catch (ResponseBudgetExceededException exhausted) {
                return new CollectionResult(result, "PARTIAL", "RESPONSE_BYTE_BUDGET_EXHAUSTED");
            }
            boolean reachedWindowStart = false;
            if (body.path("data").isArray()) for (JsonNode run : body.path("data")) {
                String id = text(run, "id"); if (id == null) continue;
                Instant createdAt = instant(run, "created_at");
                if (createdAt != null && createdAt.isBefore(after)) { reachedWindowStart = true; continue; }
                result.add(new Execution(id, agentName(run), agentVersion(run), createdAt, instant(run, "completed_at"), text(run, "status"),
                        null, null, null, null,
                        run.path("usage").path("total_tokens").isNumber() ? run.path("usage").path("total_tokens").asLong() : null,
                        null));
            }
            String last = text(body, "last_id");
            next = !reachedWindowStart && body.path("has_more").asBoolean(false) && last != null
                    ? base.resolve("openai/v1/responses?limit=100&order=desc&after=" + encode(last)) : null;
        }
        return new CollectionResult(result, "COMPLETE", null);
    }
    private JsonNode get(TokenCredential credential, URI uri) { try {
        AccessToken token = credential.getToken(new TokenRequestContext().addScopes("https://ai.azure.com/.default")).block(Duration.ofSeconds(20));
        HttpResponse<String> response = http.send(HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(30)).header("Authorization", "Bearer " + token.getToken()).header("Accept", "application/json").GET().build(), HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) throw new IllegalStateException("Foundry runtime request failed: " + response.statusCode());
        if (response.body().length() > 4_000_000) throw new ResponseBudgetExceededException(); return json.readTree(response.body());
    } catch (RuntimeException error) { throw error; } catch (Exception error) { throw new IllegalStateException("Foundry runtime request failed", error); } }
    private static void validate(URI uri) { String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(); if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getUserInfo() != null || !(host.endsWith(".ai.azure.com") || host.endsWith(".services.ai.azure.com"))) throw new IllegalArgumentException("Foundry runtime endpoint is not allowlisted"); }
    private static void validatePage(URI uri, URI base) {
        validate(uri);
        if (!uri.getHost().equalsIgnoreCase(base.getHost()) || !uri.getPath().startsWith(base.getPath() + "openai/v1/responses")) {
            throw new IllegalArgumentException("Foundry runtime pagination URL is not allowlisted");
        }
    }
    private static String text(JsonNode node, String field) { return node.path(field).isTextual() ? node.path(field).asText() : null; }
    private static String agentName(JsonNode node) { return text(node.path("agent_reference"), "name"); }
    private static String agentVersion(JsonNode node) { return text(node.path("agent_reference"), "version"); }
    private static String encode(String value) { return java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8); }
    private static Instant instant(JsonNode node, String field) { try {
        JsonNode value = node.path(field);
        if (value.isIntegralNumber()) return Instant.ofEpochSecond(value.asLong());
        return value.isTextual() ? Instant.parse(value.asText()) : null;
    } catch (RuntimeException ignored) { return null; } }
    public record Execution(String id, String agentReference, String agentVersionReference, Instant startedAt,
                            Instant completedAt, String status, String outcomeCategory, String approvalState,
                            String policyState, String classification, Long tokenCount, Long latencyMs) { }
    public record CollectionResult(List<Execution> executions, String status, String diagnostic) { }
    private static final class ResponseBudgetExceededException extends RuntimeException { }
}
