package com.prototype.vulnwatch.client;

import jakarta.annotation.PostConstruct;
import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

@Component
public class GithubTokenProvider {

    private static final String DEFAULT_LOCAL_TOKEN_PATH = "./secrets/github-api-token";
    private static final String DEFAULT_LOCAL_TOKEN_DISPLAY = "backend/secrets/github-api-token";

    private final Path localTokenPath;

    @Value("${app.github.api-token:}")
    private String apiToken;

    @Value("${app.github.api-token-file:}")
    private String apiTokenFile;

    public GithubTokenProvider() {
        this(Path.of(DEFAULT_LOCAL_TOKEN_PATH));
    }

    GithubTokenProvider(Path localTokenPath) {
        this.localTokenPath = localTokenPath;
    }

    @PostConstruct
    void validateConfiguredTokenFile() {
        if (apiTokenFile == null || apiTokenFile.isBlank()) {
            return;
        }
        readRequiredSecret(Path.of(apiTokenFile.trim()), "GitHub API token file");
    }

    public String currentToken() {
        if (apiTokenFile != null && !apiTokenFile.isBlank()) {
            return readRequiredSecret(Path.of(apiTokenFile.trim()), "GitHub API token file");
        }
        String localToken = readOptionalSecret(localTokenPath);
        if (!localToken.isBlank()) {
            return localToken;
        }
        return apiToken == null ? "" : apiToken.trim();
    }

    public boolean hasToken() {
        return !currentToken().isBlank();
    }

    public void applyBearerAuth(HttpHeaders headers) {
        String token = currentToken();
        if (!token.isBlank()) {
            headers.setBearerAuth(token);
        }
    }

    public String configurationHint() {
        return "Configure GITHUB_API_TOKEN_FILE, " + DEFAULT_LOCAL_TOKEN_DISPLAY + ", or GITHUB_API_TOKEN for the backend.";
    }

    private String readRequiredSecret(Path path, String label) {
        try {
            return Files.readString(path).trim();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to read " + label, e);
        }
    }

    private String readOptionalSecret(Path path) {
        if (!Files.isRegularFile(path)) {
            return "";
        }
        try {
            return Files.readString(path).trim();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to read local GitHub API token file", e);
        }
    }
}
