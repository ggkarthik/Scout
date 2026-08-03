package com.prototype.vulnwatch.aisecurity.controller;

import com.prototype.vulnwatch.aisecurity.service.AiGridApiService;
import com.prototype.vulnwatch.aisecurity.service.AiGridHostContextService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAccessService;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.security.Principal;
import java.util.List;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Authenticated ingestion contract for Scout-managed CIEM, DSPM, ASM, and runtime evidence producers. */
@RestController
@RequestMapping("/api/internal/ai-grid/evidence")
@PreAuthorize("hasRole('SERVICE_ACCOUNT')")
public class AiGridEvidenceIngestionController {
    private final WorkspaceService workspaces;
    private final AiGridApiService api;
    private final AiSecurityAccessService access;

    public AiGridEvidenceIngestionController(WorkspaceService workspaces, AiGridApiService api,
                                             AiSecurityAccessService access) {
        this.workspaces = workspaces;
        this.api = api;
        this.access = access;
    }

    @PostMapping("/{producerId}")
    public List<AiGridHostContextService.HostFact> ingest(@PathVariable String producerId,
                                                           @RequestBody EvidenceBatch request,
                                                           Principal principal) {
        if (principal == null || !producerId.equals(principal.getName())) {
            throw new AccessDeniedException("Authenticated service account is not authorized for this producer");
        }
        return api.ingestTrustedEvidence(tenant(), producerId, request.items());
    }

    private Tenant tenant() {
        Tenant tenant = workspaces.getWorkspace();
        access.assertEntitled(tenant);
        return tenant;
    }

    public record EvidenceBatch(List<AiGridApiService.TrustedEvidenceItem> items) {}
}
