package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.UpgradeRecommendationRequest;
import com.prototype.vulnwatch.dto.UpgradeRecommendationResponse;
import com.prototype.vulnwatch.service.TenantEntitlementService;
import com.prototype.vulnwatch.service.UpgradeRecommendationService;
import com.prototype.vulnwatch.service.WorkspaceService;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/upgrade-recommendation")
public class UpgradeRecommendationController {

    private final UpgradeRecommendationService upgradeRecommendationService;
    private final WorkspaceService workspaceService;
    private final TenantEntitlementService tenantEntitlementService;

    public UpgradeRecommendationController(
            UpgradeRecommendationService upgradeRecommendationService,
            WorkspaceService workspaceService,
            TenantEntitlementService tenantEntitlementService
    ) {
        this.upgradeRecommendationService = upgradeRecommendationService;
        this.workspaceService = workspaceService;
        this.tenantEntitlementService = tenantEntitlementService;
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    public UpgradeRecommendationResponse getRecommendation(
        @RequestBody UpgradeRecommendationRequest request
    ) {
        if (!tenantEntitlementService.isEnabled(workspaceService.getWorkspace(), TenantEntitlementService.AI_UPGRADE_RECOMMENDATION)) {
            throw new org.springframework.web.server.ResponseStatusException(HttpStatus.FORBIDDEN, "AI upgrade recommendations are available in this workspace.");
        }
        return upgradeRecommendationService.getRecommendation(request);
    }
}
