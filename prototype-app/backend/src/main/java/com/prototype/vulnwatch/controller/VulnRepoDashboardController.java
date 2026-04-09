package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.VulnRepoDashboardResponse;
import com.prototype.vulnwatch.dto.VulnRepoSoftwareAssetsResponse;
import java.util.UUID;
import com.prototype.vulnwatch.service.VulnRepoDashboardService;
import com.prototype.vulnwatch.service.WorkspaceService;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/vuln-repo")
public class VulnRepoDashboardController {

    private final WorkspaceService workspaceService;
    private final VulnRepoDashboardService vulnRepoDashboardService;

    public VulnRepoDashboardController(
            WorkspaceService workspaceService,
            VulnRepoDashboardService vulnRepoDashboardService
    ) {
        this.workspaceService = workspaceService;
        this.vulnRepoDashboardService = vulnRepoDashboardService;
    }

    @GetMapping("/dashboard")
    public VulnRepoDashboardResponse getDashboard() {
        return vulnRepoDashboardService.get(workspaceService.getWorkspace());
    }

    @GetMapping("/software-assets/{softwareIdentityId}")
    public VulnRepoSoftwareAssetsResponse getSoftwareAssets(@PathVariable UUID softwareIdentityId) {
        return vulnRepoDashboardService.getSoftwareAssets(workspaceService.getWorkspace(), softwareIdentityId);
    }
}
