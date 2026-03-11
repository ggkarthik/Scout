package com.prototype.vulnwatch.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.http.HttpHeaders;
import org.springframework.test.util.ReflectionTestUtils;

class GithubTokenProviderTest {

    @TempDir
    Path tempDir;

    @Test
    void currentToken_prefersConfiguredFileOverLocalFallbackAndInlineToken() throws Exception {
        Path configuredTokenFile = tempDir.resolve("configured-token.txt");
        Path localFallbackFile = tempDir.resolve("local-token.txt");
        Files.writeString(configuredTokenFile, "configured-token");
        Files.writeString(localFallbackFile, "local-token");

        GithubTokenProvider provider = new GithubTokenProvider(localFallbackFile);
        ReflectionTestUtils.setField(provider, "apiToken", "inline-token");
        ReflectionTestUtils.setField(provider, "apiTokenFile", configuredTokenFile.toString());

        assertEquals("configured-token", provider.currentToken());
    }

    @Test
    void currentToken_usesLocalFallbackBeforeInlineToken() throws Exception {
        Path localFallbackFile = tempDir.resolve("local-token.txt");
        Files.writeString(localFallbackFile, "local-token");

        GithubTokenProvider provider = new GithubTokenProvider(localFallbackFile);
        ReflectionTestUtils.setField(provider, "apiToken", "inline-token");
        ReflectionTestUtils.setField(provider, "apiTokenFile", "");

        assertEquals("local-token", provider.currentToken());

        HttpHeaders headers = new HttpHeaders();
        provider.applyBearerAuth(headers);
        assertEquals("Bearer local-token", headers.getFirst(HttpHeaders.AUTHORIZATION));
        assertTrue(provider.hasToken());
    }

    @Test
    void hasToken_isFalseWhenNoTokenSourceExists() {
        GithubTokenProvider provider = new GithubTokenProvider(tempDir.resolve("missing-token.txt"));
        ReflectionTestUtils.setField(provider, "apiToken", "");
        ReflectionTestUtils.setField(provider, "apiTokenFile", "");

        assertFalse(provider.hasToken());
        assertEquals("", provider.currentToken());
    }
}
