package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.UpgradeRecommendationRequest;
import com.prototype.vulnwatch.dto.UpgradeRecommendationResponse;
import com.prototype.vulnwatch.service.EntitlementGuard;
import com.prototype.vulnwatch.service.TenantEntitlementService;
import com.prototype.vulnwatch.service.UpgradeRecommendationService;
import com.prototype.vulnwatch.service.WorkspaceService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/upgrade-recommendation")
public class UpgradeRecommendationController {

    private final UpgradeRecommendationService upgradeRecommendationService;
    private final WorkspaceService workspaceService;
    private final EntitlementGuard entitlementGuard;

    public UpgradeRecommendationController(
            UpgradeRecommendationService upgradeRecommendationService,
            WorkspaceService workspaceService,
            EntitlementGuard entitlementGuard
    ) {
        this.upgradeRecommendationService = upgradeRecommendationService;
        this.workspaceService = workspaceService;
        this.entitlementGuard = entitlementGuard;
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    public UpgradeRecommendationResponse getRecommendation(
        @RequestBody UpgradeRecommendationRequest request
    ) {
        entitlementGuard.assertEnabled(
                workspaceService.getWorkspace(),
                TenantEntitlementService.AI_UPGRADE_RECOMMENDATION,
                "AI upgrade recommendations are available on the Enterprise plan.");
        return upgradeRecommendationService.getRecommendation(request);
    }
}
