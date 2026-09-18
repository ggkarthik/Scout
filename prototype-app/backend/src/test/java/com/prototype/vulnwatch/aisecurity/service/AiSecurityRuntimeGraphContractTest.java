package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

class AiSecurityRuntimeGraphContractTest {
    @Test
    void omitsRuntimeOverlayFromLegacyGraphJson() throws Exception {
        var response = new AiSecurityApiService.GraphResponse(List.of(), List.of(), false, null);
        String json = new ObjectMapper().writeValueAsString(response);
        assertFalse(json.contains("runtimeOverlay"));
        assertEquals("{\"nodes\":[],\"edges\":[],\"truncated\":false}", json);
    }

    @Test
    void validatesRuntimeWindowsWithoutChangingDefinitionOnlyRequests() {
        UUID root = UUID.randomUUID();
        Instant to = Instant.parse("2026-09-17T10:00:00Z");
        Instant from = to.minusSeconds(7 * 24 * 60 * 60L);
        assertNull(AiSecurityApiService.runtimeWindow(null, false, null, null));
        assertEquals(new AiSecurityApiService.RuntimeWindow(from, to),
                AiSecurityApiService.runtimeWindow(root, true, from, to));
        assertThrows(ResponseStatusException.class,
                () -> AiSecurityApiService.runtimeWindow(null, true, from, to));
        assertThrows(ResponseStatusException.class,
                () -> AiSecurityApiService.runtimeWindow(root, true, to, from));
        assertThrows(ResponseStatusException.class,
                () -> AiSecurityApiService.runtimeWindow(root, true, to.minusSeconds(91 * 24 * 60 * 60L), to));
    }
}
