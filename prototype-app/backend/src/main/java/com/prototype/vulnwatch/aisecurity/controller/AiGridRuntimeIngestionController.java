package com.prototype.vulnwatch.aisecurity.controller;

import com.prototype.vulnwatch.aisecurity.service.AiGridRuntimeIngestionService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAccessService;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.security.Principal;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/internal/ai-grid/runtime")
@PreAuthorize("hasRole('SERVICE_ACCOUNT')")
public class AiGridRuntimeIngestionController {
    private final WorkspaceService workspaces;
    private final AiSecurityAccessService access;
    private final AiGridRuntimeIngestionService ingestion;

    public AiGridRuntimeIngestionController(WorkspaceService workspaces, AiSecurityAccessService access,
                                            AiGridRuntimeIngestionService ingestion) {
        this.workspaces = workspaces;
        this.access = access;
        this.ingestion = ingestion;
    }

    @PostMapping("/{producerId}/v1/batches")
    public ResponseEntity<AiGridRuntimeIngestionService.AdmissionResult> ingest(
            @PathVariable String producerId, @RequestBody byte[] request, Principal principal) {
        if (principal == null || !producerId.equals(principal.getName())) {
            throw new AccessDeniedException("Authenticated service account is not authorized for this producer");
        }
        Tenant tenant = workspaces.getWorkspace();
        access.assertEntitled(tenant);
        AiGridRuntimeIngestionService.AdmissionResult result = ingestion.accept(tenant, producerId, request);
        if (!"REJECTED".equals(result.status())) {
            return ResponseEntity.accepted().body(result);
        }
        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.RETRY_AFTER, Integer.toString(result.retryAfterSeconds() == null ? 30 : result.retryAfterSeconds()));
        return new ResponseEntity<>(result, headers, HttpStatus.TOO_MANY_REQUESTS);
    }
}
