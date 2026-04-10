package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Locale;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

final class ServiceNowApiResponseParser {

    private ServiceNowApiResponseParser() {
    }

    static JsonNode parseJson(ObjectMapper objectMapper, ResponseEntity<String> response, String contextLabel) {
        String body = response.getBody();
        if (body == null || body.isBlank()) {
            throw new IllegalStateException(contextLabel + " returned an empty response");
        }

        String trimmed = body.stripLeading();
        if (trimmed.startsWith("<")) {
            throw new IllegalStateException(
                    contextLabel + " returned HTML instead of JSON. Check the ServiceNow base URL, credentials, and API access."
            );
        }

        MediaType contentType = response.getHeaders().getContentType();
        if (contentType != null && !isJsonLike(contentType) && !looksLikeJson(trimmed)) {
            throw new IllegalStateException(
                    contextLabel + " returned " + contentType + " instead of JSON. Response preview: " + preview(trimmed)
            );
        }

        try {
            return objectMapper.readTree(body);
        } catch (Exception exception) {
            throw new IllegalStateException(
                    contextLabel + " returned invalid JSON. Response preview: " + preview(trimmed),
                    exception
            );
        }
    }

    private static boolean isJsonLike(MediaType contentType) {
        return MediaType.APPLICATION_JSON.isCompatibleWith(contentType)
                || contentType.getSubtype().toLowerCase(Locale.ROOT).endsWith("+json");
    }

    private static boolean looksLikeJson(String body) {
        return body.startsWith("{") || body.startsWith("[");
    }

    private static String preview(String body) {
        String collapsed = body.replaceAll("\\s+", " ").trim();
        if (collapsed.length() <= 120) {
            return collapsed;
        }
        return collapsed.substring(0, 117) + "...";
    }
}
