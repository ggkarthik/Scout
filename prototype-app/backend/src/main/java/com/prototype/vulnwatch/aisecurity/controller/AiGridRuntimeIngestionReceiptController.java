package com.prototype.vulnwatch.aisecurity.controller;

import com.prototype.vulnwatch.aisecurity.service.AiGridRuntimeIngestionService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAccessService;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/ai-security/runtime-ingestion/receipts")
public class AiGridRuntimeIngestionReceiptController {
    private final WorkspaceService workspaces;
    private final AiSecurityAccessService access;
    private final AiGridRuntimeIngestionService ingestion;

    public AiGridRuntimeIngestionReceiptController(WorkspaceService workspaces, AiSecurityAccessService access,
                                                   AiGridRuntimeIngestionService ingestion) {
        this.workspaces = workspaces;
        this.access = access;
        this.ingestion = ingestion;
    }

    @GetMapping("/{receiptId}")
    public AiGridRuntimeIngestionService.Receipt receipt(@PathVariable UUID receiptId) {
        Tenant tenant = workspaces.getWorkspace();
        access.assertEntitled(tenant);
        AiGridRuntimeIngestionService.Receipt receipt = ingestion.receipt(tenant, receiptId);
        if (receipt == null) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Runtime ingestion receipt not found");
        return receipt;
    }
}
