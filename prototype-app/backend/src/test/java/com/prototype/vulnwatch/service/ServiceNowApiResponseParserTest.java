package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

class ServiceNowApiResponseParserTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void parsesValidJsonPayload() {
        ResponseEntity<String> response = ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .body("{\"result\":[]}");

        JsonNode root = ServiceNowApiResponseParser.parseJson(objectMapper, response, "ServiceNow table cmdb_ci");

        assertTrue(root.has("result"));
        assertEquals(0, root.path("result").size());
    }

    @Test
    void failsGracefullyWhenHtmlIsReturned() {
        ResponseEntity<String> response = ResponseEntity.ok()
                .contentType(MediaType.TEXT_HTML)
                .body("<html><body>login required</body></html>");

        IllegalStateException exception = assertThrows(
                IllegalStateException.class,
                () -> ServiceNowApiResponseParser.parseJson(objectMapper, response, "ServiceNow table cmdb_ci")
        );

        assertTrue(exception.getMessage().contains("returned HTML instead of JSON"));
    }
}
