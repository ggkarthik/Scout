package com.prototype.vulnwatch.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

@Component
public class GithubApiClient {

    public record GithubSbomResponse(
            byte[] payload,
            Integer statusCode,
            String contentType,
            long contentLength,
            String endpoint
    ) {
    }

    public record GithubRepositoryRef(
            String owner,
            String repo,
            String fullName,
            String htmlUrl,
            boolean privateRepo,
            String defaultBranch
    ) {
    }

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    @Value("${app.github.base-url:https://api.github.com}")
    private String baseUrl;

    @Value("${app.github.api-token:}")
    private String apiToken;

    @Value("${app.github.api-token-file:}")
    private String apiTokenFile;

    @Value("${app.github.allowlist-enabled:true}")
    private boolean allowlistEnabled;

    @Value("${app.github.allowed-repos:}")
    private String allowedReposCsv;

    @Value("${app.github.max-retries:4}")
    private int maxRetries;

    @Value("${app.github.retry-base-backoff-ms:1000}")
    private long retryBaseBackoffMs;

    private String resolvedToken = "";
    private Set<String> allowedRepos = Set.of();

    public GithubApiClient(RestTemplate restTemplate, ObjectMapper objectMapper) {
        this.restTemplate = restTemplate;
        this.objectMapper = objectMapper;
    }

    @PostConstruct
    public void init() {
        this.resolvedToken = resolveToken();
        this.allowedRepos = parseAllowedRepos();
    }

    public boolean hasToken() {
        return resolvedToken != null && !resolvedToken.isBlank();
    }

    public GithubSbomResponse fetchGeneratedSbom(String owner, String repo) throws IOException {
        String normalizedOwner = normalize(owner);
        String normalizedRepo = normalize(repo);
        assertAllowed(normalizedOwner, normalizedRepo);

        String endpoint = buildGeneratedSbomEndpoint(normalizedOwner, normalizedRepo);
        ResponseEntity<byte[]> response = exchangeWithRetry(endpoint, byte[].class, "GitHub SBOM API");
        byte[] payload = response.getBody();
        if (payload == null || payload.length == 0) {
            throw new IOException("GitHub generated SBOM response was empty");
        }
        long contentLength = response.getHeaders().getContentLength() >= 0
                ? response.getHeaders().getContentLength()
                : payload.length;
        return new GithubSbomResponse(
                payload,
                response.getStatusCode().value(),
                response.getHeaders().getFirst(HttpHeaders.CONTENT_TYPE),
                contentLength,
                endpoint
        );
    }

    public List<GithubRepositoryRef> listAccountRepositories(String account) throws IOException {
        String normalizedAccount = normalize(account);
        if (normalizedAccount.isBlank()) {
            throw new IOException("GitHub account owner is required");
        }
        Map<String, GithubRepositoryRef> merged = new LinkedHashMap<>();
        boolean orgNotFound = false;
        boolean userNotFound = false;

        try {
            for (GithubRepositoryRef repo : listRepositoriesByEndpoint(buildOrgReposEndpoint(normalizedAccount))) {
                if (isAllowed(repo.owner(), repo.repo())) {
                    merged.put(repo.owner() + "/" + repo.repo(), repo);
                }
            }
        } catch (GithubNotFoundException e) {
            orgNotFound = true;
        }

        try {
            for (GithubRepositoryRef repo : listRepositoriesByEndpoint(buildUserReposEndpoint(normalizedAccount))) {
                if (isAllowed(repo.owner(), repo.repo())) {
                    merged.put(repo.owner() + "/" + repo.repo(), repo);
                }
            }
        } catch (GithubNotFoundException e) {
            userNotFound = true;
        }

        if (merged.isEmpty() && orgNotFound && userNotFound) {
            throw new IOException("GitHub account was not found or is inaccessible: " + normalizedAccount);
        }
        return new ArrayList<>(merged.values());
    }

    public String buildGeneratedSbomEndpoint(String owner, String repo) {
        return UriComponentsBuilder.fromHttpUrl(baseUrl)
                .pathSegment("repos", normalize(owner), normalize(repo), "dependency-graph", "sbom")
                .build()
                .toUriString();
    }

    private void assertAllowed(String owner, String repo) throws IOException {
        if (!isAllowed(owner, repo)) {
            throw new IOException("GitHub repository is not allowlisted: " + owner + "/" + repo);
        }
    }

    private boolean isAllowed(String owner, String repo) {
        if (!allowlistEnabled) {
            return true;
        }
        // Enforce allowlist only when entries are configured.
        // This avoids hard-failing ingestion in environments that have not configured explicit repo restrictions yet.
        if (allowedRepos.isEmpty()) {
            return true;
        }
        String key = owner + "/" + repo;
        return allowedRepos.contains(key);
    }

    private boolean isRetriableStatus(HttpStatusCode statusCode) {
        int status = statusCode.value();
        return status == 429 || status == 500 || status == 502 || status == 503 || status == 504;
    }

    private void sleepForRetry(int attempt, String retryAfterHeader) {
        long sleepMs = -1;
        if (retryAfterHeader != null && !retryAfterHeader.isBlank()) {
            try {
                sleepMs = Math.max(0, Long.parseLong(retryAfterHeader.trim()) * 1000L);
            } catch (NumberFormatException ignored) {
                sleepMs = -1;
            }
        }
        if (sleepMs < 0) {
            long base = Math.max(200L, retryBaseBackoffMs);
            long jitter = ThreadLocalRandom.current().nextLong(200L, 900L);
            sleepMs = Math.min(15000L, (long) (base * Math.pow(2, Math.max(0, attempt - 1))) + jitter);
        }
        try {
            Thread.sleep(sleepMs);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }

    private Set<String> parseAllowedRepos() {
        if (allowedReposCsv == null || allowedReposCsv.isBlank()) {
            return Set.of();
        }
        Set<String> values = new HashSet<>();
        for (String value : allowedReposCsv.split(",")) {
            if (value == null || value.isBlank()) {
                continue;
            }
            String normalized = value.trim().toLowerCase(Locale.ROOT);
            if (!normalized.contains("/")) {
                continue;
            }
            values.add(normalized);
        }
        return values;
    }

    private String resolveToken() {
        String fileValue = readSecretFromFile(apiTokenFile);
        if (!fileValue.isBlank()) {
            return fileValue;
        }
        return apiToken == null ? "" : apiToken.trim();
    }

    private String readSecretFromFile(String pathValue) {
        if (pathValue == null || pathValue.isBlank()) {
            return "";
        }
        try {
            return Files.readString(Path.of(pathValue.trim())).trim();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to read GitHub API token file", e);
        }
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    private String buildOrgReposEndpoint(String account) {
        return UriComponentsBuilder.fromHttpUrl(baseUrl)
                .pathSegment("orgs", account, "repos")
                .build()
                .toUriString();
    }

    private String buildUserReposEndpoint(String account) {
        return UriComponentsBuilder.fromHttpUrl(baseUrl)
                .pathSegment("users", account, "repos")
                .build()
                .toUriString();
    }

    private List<GithubRepositoryRef> listRepositoriesByEndpoint(String endpointBase) throws IOException {
        List<GithubRepositoryRef> repositories = new ArrayList<>();
        for (int page = 1; page <= 1000; page++) {
            String endpoint = UriComponentsBuilder.fromHttpUrl(endpointBase)
                    .queryParam("per_page", 100)
                    .queryParam("page", page)
                    .queryParam("type", "all")
                    .build()
                    .toUriString();
            ResponseEntity<String> response = exchangeWithRetry(endpoint, String.class, "GitHub repositories API");
            String payload = response.getBody();
            JsonNode root;
            try {
                root = objectMapper.readTree(payload == null ? "[]" : payload);
            } catch (Exception e) {
                throw new IOException("Failed to parse GitHub repository list response", e);
            }
            if (!root.isArray()) {
                throw new IOException("Unexpected GitHub repository list response format");
            }
            if (root.isEmpty()) {
                break;
            }
            for (JsonNode entry : root) {
                JsonNode ownerNode = entry.path("owner");
                String owner = normalize(ownerNode.path("login").asText(""));
                String repo = normalize(entry.path("name").asText(""));
                if (owner.isBlank() || repo.isBlank()) {
                    continue;
                }
                repositories.add(new GithubRepositoryRef(
                        owner,
                        repo,
                        entry.path("full_name").asText(owner + "/" + repo),
                        entry.path("html_url").asText(""),
                        entry.path("private").asBoolean(false),
                        entry.path("default_branch").asText("")));
            }
            if (root.size() < 100) {
                break;
            }
        }
        return repositories;
    }

    private <T> ResponseEntity<T> exchangeWithRetry(
            String endpoint,
            Class<T> responseType,
            String operationName
    ) throws IOException {
        int attempts = Math.max(1, maxRetries);
        Exception lastError = null;
        for (int attempt = 1; attempt <= attempts; attempt++) {
            try {
                return restTemplate.exchange(
                        endpoint,
                        HttpMethod.GET,
                        new HttpEntity<>(buildHeaders()),
                        responseType);
            } catch (HttpStatusCodeException ex) {
                lastError = ex;
                if (ex.getStatusCode().value() == 404) {
                    throw new GithubNotFoundException(operationName + " request returned 404", ex);
                }
                if (!isRetriableStatus(ex.getStatusCode()) || attempt == attempts) {
                    throw new IOException(operationName + " request failed with status " + ex.getStatusCode().value(), ex);
                }
                sleepForRetry(attempt, ex.getResponseHeaders() == null ? null : ex.getResponseHeaders().getFirst("Retry-After"));
            } catch (Exception ex) {
                lastError = ex;
                if (attempt == attempts) {
                    break;
                }
                sleepForRetry(attempt, null);
            }
        }
        throw new IOException("Failed to call " + operationName + " after retries", lastError);
    }

    private HttpHeaders buildHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        headers.set("X-GitHub-Api-Version", "2022-11-28");
        if (hasToken()) {
            headers.setBearerAuth(resolvedToken);
        }
        return headers;
    }

    private static final class GithubNotFoundException extends IOException {
        private GithubNotFoundException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
