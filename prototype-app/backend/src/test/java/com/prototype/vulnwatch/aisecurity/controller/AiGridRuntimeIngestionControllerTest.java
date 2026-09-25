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
    void returnsRetryAfterWhenTenantQuotaIsExhausted() {
        Tenant tenant = mock(Tenant.class);
        when(workspaces.getWorkspace()).thenReturn(tenant);
        when(ingestion.accept(eq(tenant), eq("runtime-producer"), any(byte[].class)))
                .thenReturn(new AiGridRuntimeIngestionService.AdmissionResult(UUID.randomUUID(), "REJECTED",
                        0, 0, 0, "TENANT_QUOTA_EXHAUSTED", 47));

        var response = controller.ingest("runtime-producer", new byte[] {1}, () -> "runtime-producer");

        assertEquals(HttpStatus.TOO_MANY_REQUESTS, response.getStatusCode());
        assertEquals("47", response.getHeaders().getFirst("Retry-After"));
    }
}
