package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CbomComponentResponse;
import com.prototype.vulnwatch.dto.CbomPostureSummaryResponse;
import com.prototype.vulnwatch.dto.CbomRiskFindingResponse;
import com.prototype.vulnwatch.service.WorkspaceService;
import com.prototype.vulnwatch.service.cbom.CbomReadService;
import java.util.List;
import java.util.UUID;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/bom/cbom")
public class CbomController {

    private final WorkspaceService workspaceService;
    private final CbomReadService cbomReadService;

    public CbomController(WorkspaceService workspaceService, CbomReadService cbomReadService) {
        this.workspaceService = workspaceService;
        this.cbomReadService = cbomReadService;
    }

    @GetMapping("/posture")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','CREATOR','OPERATOR')")
    public List<CbomPostureSummaryResponse> listPosture() {
        Tenant tenant = workspaceService.getWorkspace();
        return cbomReadService.listPosture(tenant);
    }

    @GetMapping("/posture/{assetId}")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','CREATOR','OPERATOR')")
    public CbomPostureSummaryResponse getPosture(@PathVariable UUID assetId) {
        Tenant tenant = workspaceService.getWorkspace();
        return cbomReadService.getPosture(tenant, assetId);
    }

    @GetMapping("/components")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','CREATOR','OPERATOR')")
    public List<CbomComponentResponse> listComponents(
            @RequestParam UUID assetId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "100") int size
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        return cbomReadService.listComponents(tenant, assetId, page, size);
    }

    @GetMapping("/findings")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','CREATOR','OPERATOR')")
    public List<CbomRiskFindingResponse> listFindings(
            @RequestParam UUID assetId,
            @RequestParam(required = false) String severity
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        return cbomReadService.listFindings(tenant, assetId, severity);
    }

    @PostMapping("/findings/{findingId}/accept")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','TENANT_ADMIN','CREATOR')")
    public CbomRiskFindingResponse acceptFinding(@PathVariable UUID findingId) {
        Tenant tenant = workspaceService.getWorkspace();
        return cbomReadService.acceptFinding(tenant, findingId);
    }
}
