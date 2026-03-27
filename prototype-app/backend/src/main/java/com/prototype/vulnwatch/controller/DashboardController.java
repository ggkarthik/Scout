package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.ApplicableSoftwarePageResponse;
import com.prototype.vulnwatch.dto.DashboardCveInventoryMapResponse;
import com.prototype.vulnwatch.dto.DashboardResponse;
import com.prototype.vulnwatch.dto.ImpactedCvePageResponse;
import com.prototype.vulnwatch.service.DashboardService;
import com.prototype.vulnwatch.service.WorkspaceService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/dashboard")
public class DashboardController {

    private final WorkspaceService workspaceService;
    private final DashboardService dashboardService;

    public DashboardController(WorkspaceService workspaceService, DashboardService dashboardService) {
        this.workspaceService = workspaceService;
        this.dashboardService = dashboardService;
    }

    @GetMapping
    public DashboardResponse get() {
        Tenant tenant = workspaceService.getWorkspace();
        return dashboardService.get(tenant);
    }

    @GetMapping("/applicable-software")
    public ApplicableSoftwarePageResponse listApplicableSoftware(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "25") int size
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        return dashboardService.listApplicableSoftware(tenant, page, size);
    }

    @GetMapping("/impacted-cves")
    public ImpactedCvePageResponse listImpactedCves(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "25") int size
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        return dashboardService.listImpactedCves(tenant, page, size);
    }

    @GetMapping("/cve-inventory-map")
    public DashboardCveInventoryMapResponse getCveInventoryMap(
            @RequestParam(defaultValue = "5") int limit
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        return dashboardService.getCveInventoryMap(tenant, limit);
    }
}
