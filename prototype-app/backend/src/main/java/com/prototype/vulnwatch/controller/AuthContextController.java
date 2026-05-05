package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.AuthContextResponse;
import com.prototype.vulnwatch.dto.DemoStatusResponse;
import com.prototype.vulnwatch.service.DemoLifecycleService;
import com.prototype.vulnwatch.service.RequestActor;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.WorkspaceService;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class AuthContextController {

    private final RequestActorService requestActorService;
    private final WorkspaceService workspaceService;
    private final ObjectProvider<DemoLifecycleService> demoLifecycleServiceProvider;

    public AuthContextController(
            RequestActorService requestActorService,
            WorkspaceService workspaceService,
            ObjectProvider<DemoLifecycleService> demoLifecycleServiceProvider
    ) {
        this.requestActorService = requestActorService;
        this.workspaceService = workspaceService;
        this.demoLifecycleServiceProvider = demoLifecycleServiceProvider;
    }

    @GetMapping({"/auth/context", "/me"})
    public AuthContextResponse get() {
        RequestActor actor = requestActorService.currentActor();
        DemoLifecycleService demoLifecycleService = demoLifecycleServiceProvider.getIfAvailable();
        DemoStatusResponse demoStatus = actor.tenantId() == null || demoLifecycleService == null
                ? null
                : demoLifecycleService.statusForTenant(workspaceService.getWorkspace());
        return new AuthContextResponse(
                actor.creator(),
                actor.userId(),
                actor.userId(),
                actor.tenantId() == null ? null : actor.tenantId().toString(),
                actor.tenantName(),
                actor.roles(),
                demoStatus == null ? null : demoStatus.planCode(),
                demoStatus == null ? null : demoStatus.demoExpiresAt(),
                demoStatus == null ? null : demoStatus.demoDaysRemaining(),
                demoStatus == null ? null : demoStatus.demoCapabilities(),
                demoStatus == null ? null : demoStatus.demoUsage()
        );
    }
}
