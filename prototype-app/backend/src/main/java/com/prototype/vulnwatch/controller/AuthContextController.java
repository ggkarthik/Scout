package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.AuthContextResponse;
import com.prototype.vulnwatch.dto.DemoStatusResponse;
import com.prototype.vulnwatch.service.AllowedTenantContextService;
import com.prototype.vulnwatch.service.DemoLifecycleService;
import com.prototype.vulnwatch.service.RequestActor;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.TenantSupportGrantService;
import com.prototype.vulnwatch.service.WorkspaceService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class AuthContextController {

    private final RequestActorService requestActorService;
    private final WorkspaceService workspaceService;
    private final DemoLifecycleService demoLifecycleService;
    private final AllowedTenantContextService allowedTenantContextService;
    private final TenantSupportGrantService tenantSupportGrantService;

    public AuthContextController(
            RequestActorService requestActorService,
            WorkspaceService workspaceService,
            DemoLifecycleService demoLifecycleService,
            AllowedTenantContextService allowedTenantContextService,
            TenantSupportGrantService tenantSupportGrantService
    ) {
        this.requestActorService = requestActorService;
        this.workspaceService = workspaceService;
        this.demoLifecycleService = demoLifecycleService;
        this.allowedTenantContextService = allowedTenantContextService;
        this.tenantSupportGrantService = tenantSupportGrantService;
    }

    @GetMapping({"/auth/context", "/me"})
    public AuthContextResponse get() {
        RequestActor actor = requestActorService.currentActor();
        var activeSupportGrant = actor.actingAsPlatformOwner()
                ? tenantSupportGrantService.findActiveGrant(actor.userId(), actor.tenantId())
                : java.util.Optional.<com.prototype.vulnwatch.domain.TenantSupportGrant>empty();
        boolean validPlatformTenantSession = !actor.actingAsPlatformOwner() || activeSupportGrant.isPresent();
        DemoStatusResponse demoStatus = actor.tenantId() == null || !validPlatformTenantSession
                ? null
                : demoLifecycleService.statusForTenant(workspaceService.getWorkspace());
        var allowedTenants = allowedTenantContextService.listAllowedTenants(actor);
        String tenantId = validPlatformTenantSession ? actor.tenantId() == null ? null : actor.tenantId().toString() : null;
        String tenantName = validPlatformTenantSession ? actor.tenantName() : null;
        return new AuthContextResponse(
                actor.creator(),
                actor.userId(),
                actor.userId(),
                tenantId,
                tenantName,
                actor.roles(),
                allowedTenants,
                actor.platformScope() || !validPlatformTenantSession,
                validPlatformTenantSession && actor.actingAsPlatformOwner(),
                validPlatformTenantSession && actor.actingAsPlatformOwner(),
                activeSupportGrant.map(com.prototype.vulnwatch.domain.TenantSupportGrant::getAccessMode).orElse(null),
                activeSupportGrant.map(com.prototype.vulnwatch.domain.TenantSupportGrant::getExpiresAt).orElse(null),
                demoStatus == null ? null : demoStatus.planCode(),
                demoStatus == null ? null : demoStatus.demoExpiresAt(),
                demoStatus == null ? null : demoStatus.demoDaysRemaining(),
                demoStatus == null ? null : demoStatus.demoCapabilities(),
                demoStatus == null ? null : demoStatus.demoUsage()
        );
    }
}
