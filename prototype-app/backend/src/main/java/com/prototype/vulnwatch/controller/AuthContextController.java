package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.AuthContextResponse;
import com.prototype.vulnwatch.dto.DemoStatusResponse;
import com.prototype.vulnwatch.service.AllowedTenantContextService;
import com.prototype.vulnwatch.service.DemoLifecycleService;
import com.prototype.vulnwatch.service.RequestActor;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.TenantEntitlementService;
import com.prototype.vulnwatch.service.WorkspaceService;
import com.prototype.vulnwatch.domain.Tenant;
import java.util.Map;
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
    private final TenantEntitlementService tenantEntitlementService;

    public AuthContextController(
            RequestActorService requestActorService,
            WorkspaceService workspaceService,
            DemoLifecycleService demoLifecycleService,
            AllowedTenantContextService allowedTenantContextService,
            TenantEntitlementService tenantEntitlementService
    ) {
        this.requestActorService = requestActorService;
        this.workspaceService = workspaceService;
        this.demoLifecycleService = demoLifecycleService;
        this.allowedTenantContextService = allowedTenantContextService;
        this.tenantEntitlementService = tenantEntitlementService;
    }

    @GetMapping({"/auth/context", "/me"})
    public AuthContextResponse get() {
        RequestActor actor = requestActorService.currentActor();
        Tenant workspace = actor.tenantId() == null ? null : workspaceService.getWorkspace();
        DemoStatusResponse demoStatus = workspace == null ? null : demoLifecycleService.statusForTenant(workspace);
        var allowedTenants = allowedTenantContextService.listAllowedTenants(actor);
        String tenantId = actor.tenantId() == null ? null : actor.tenantId().toString();
        String tenantName = actor.tenantName();
        Map<String, Boolean> entitlements = workspace == null
                ? Map.of()
                : tenantEntitlementService.snapshot(workspace);
        return new AuthContextResponse(
                actor.creator(),
                actor.userId(),
                actor.userId(),
                tenantId,
                tenantName,
                actor.roles(),
                allowedTenants,
                actor.platformScope(),
                false,
                false,
                null,
                null,
                workspace == null ? null : workspace.getPlanCode(),
                entitlements,
                demoStatus == null ? null : demoStatus.demo(),
                demoStatus == null ? null : demoStatus.demoExpiresAt(),
                demoStatus == null ? null : demoStatus.demoDaysRemaining(),
                demoStatus == null ? null : demoStatus.demoCapabilities(),
                demoStatus == null ? null : demoStatus.demoUsage()
        );
    }
}
