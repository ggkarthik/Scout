package com.prototype.vulnwatch.aisecurity.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.aisecurity.service.AiGridRuntimeIngestionService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAccessService;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.security.Principal;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;

class AiGridRuntimeIngestionControllerTest {
    private final WorkspaceService workspaces = mock(WorkspaceService.class);
    private final AiSecurityAccessService access = mock(AiSecurityAccessService.class);
    private final AiGridRuntimeIngestionService ingestion = mock(AiGridRuntimeIngestionService.class);
    private final AiGridRuntimeIngestionController controller =
            new AiGridRuntimeIngestionController(workspaces, access, ingestion);

    @Test
    void requiresPathProducerToMatchAuthenticatedPrincipal() {
        Principal principal = () -> "other-producer";
        assertThrows(AccessDeniedException.class,
                () -> controller.ingest("runtime-producer", new byte[] {1}, principal));
    }

    @Test
    void rejectsAuthorizedProducerWithoutAdmittingAnyWork() {
        var error = assertThrows(org.springframework.web.server.ResponseStatusException.class,
                () -> controller.ingest("runtime-producer", new byte[] {1}, () -> "runtime-producer"));
        assertEquals(HttpStatus.GONE, error.getStatusCode());
        assertEquals("RUNTIME_OUT_OF_SCOPE", error.getReason());
        org.mockito.Mockito.verifyNoInteractions(ingestion, workspaces, access);
    }
}
