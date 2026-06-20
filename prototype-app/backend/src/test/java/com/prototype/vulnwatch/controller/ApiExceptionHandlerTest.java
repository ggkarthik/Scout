package com.prototype.vulnwatch.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.prototype.vulnwatch.service.QuotaExceededException;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

class ApiExceptionHandlerTest {

    private final ApiExceptionHandler handler = new ApiExceptionHandler();

    @Test
    void mapsResponseStatusExceptionToRequestedStatus() {
        ResponseEntity<Map<String, Object>> response = handler.handleResponseStatus(
                new ResponseStatusException(HttpStatus.BAD_REQUEST, "Token missing")
        );

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("BAD_REQUEST", response.getBody().get("code"));
        assertEquals("Token missing", response.getBody().get("error"));
    }

    @Test
    void preservesQuotaCodeAndRetryAfterOnQuotaExceeded() {
        Map<String, Object> response = handler.handleQuotaExceeded(
                new QuotaExceededException("TENANT_SBOM_RATE_LIMIT_EXCEEDED", "Too many requests", 120)
        );

        assertEquals("TENANT_SBOM_RATE_LIMIT_EXCEEDED", response.get("code"));
        assertEquals("TENANT_SBOM_RATE_LIMIT_EXCEEDED", response.get("quotaCode"));
        assertEquals(120, response.get("retryAfterSeconds"));
    }

    @Test
    void mapsAccessDeniedToForbiddenPermissionPayload() {
        Map<String, Object> response = handler.handleAccessDenied(
                new org.springframework.security.access.AccessDeniedException("Feature not enabled")
        );

        assertEquals("PERMISSION_DENIED", response.get("code"));
        assertEquals("Permission denied", response.get("error"));
    }
}
