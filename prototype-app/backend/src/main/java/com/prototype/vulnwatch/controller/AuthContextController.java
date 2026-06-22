package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.AuthContextResponse;
import com.prototype.vulnwatch.dto.DemoStatusResponse;
import com.prototype.vulnwatch.service.AllowedTenantContextService;
import com.prototype.vulnwatch.service.DemoLifecycleService;
import com.prototype.vulnwatch.service.RequestActor;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.TenantSupportGrantService;
import com.prototype.vulnwatch.service.WorkspaceService;
import com.prototype.vulnwatch.domain.Tenant;
import java.util.Optional;
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
        Tenant workspace = actor.tenantId() == null ? null : workspaceService.getWorkspace();
        DemoStatusResponse demoStatus = workspace == null ? null : demoLifecycleService.statusForTenant(workspace);
        var allowedTenants = allowedTenantContextService.listAllowedTenants(actor);
        Optional<com.prototype.vulnwatch.domain.TenantSupportGrant> activeSupportGrant =
                actor.actingAsPlatformOwner() && actor.tenantId() != null
                        ? tenantSupportGrantService.findActiveGrant(actor.userId(), actor.tenantId())
                        : Optional.empty();
        String tenantId = actor.tenantId() == null ? null : actor.tenantId().toString();
        String tenantName = actor.tenantName();
        return new AuthContextResponse(
                actor.creator(),
                actor.userId(),
                actor.userId(),
                tenantId,
                tenantName,
                actor.roles(),
                allowedTenants,
                actor.platformScope(),
                actor.actingAsPlatformOwner(),
                false,
                activeSupportGrant.map(com.prototype.vulnwatch.domain.TenantSupportGrant::getAccessMode).orElse(null),
                activeSupportGrant.map(com.prototype.vulnwatch.domain.TenantSupportGrant::getExpiresAt).orElse(null),
                workspace == null ? null : workspace.getPlanCode(),
                demoStatus == null ? null : demoStatus.demo(),
                demoStatus == null ? null : demoStatus.demoExpiresAt(),
                demoStatus == null ? null : demoStatus.demoDaysRemaining(),
                demoStatus == null ? null : demoStatus.demoCapabilities(),
                demoStatus == null ? null : demoStatus.demoUsage()
        );
    }
}
