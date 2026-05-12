package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.AuthContextResponse;
import com.prototype.vulnwatch.dto.AllowedTenantResponse;
import com.prototype.vulnwatch.dto.DemoStatusResponse;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
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
    private final ObjectProvider<TenantMembershipRepository> tenantMembershipRepositoryProvider;
    private final ObjectProvider<TenantRepository> tenantRepositoryProvider;

    public AuthContextController(
            RequestActorService requestActorService,
            WorkspaceService workspaceService,
            ObjectProvider<DemoLifecycleService> demoLifecycleServiceProvider,
            ObjectProvider<TenantMembershipRepository> tenantMembershipRepositoryProvider,
            ObjectProvider<TenantRepository> tenantRepositoryProvider
    ) {
        this.requestActorService = requestActorService;
        this.workspaceService = workspaceService;
        this.demoLifecycleServiceProvider = demoLifecycleServiceProvider;
        this.tenantMembershipRepositoryProvider = tenantMembershipRepositoryProvider;
        this.tenantRepositoryProvider = tenantRepositoryProvider;
    }

    @GetMapping({"/auth/context", "/me"})
    public AuthContextResponse get() {
        RequestActor actor = requestActorService.currentActor();
        DemoLifecycleService demoLifecycleService = demoLifecycleServiceProvider.getIfAvailable();
        DemoStatusResponse demoStatus = actor.tenantId() == null || demoLifecycleService == null
                ? null
                : demoLifecycleService.statusForTenant(workspaceService.getWorkspace());
        TenantRepository tenantRepository = tenantRepositoryProvider.getIfAvailable();
        TenantMembershipRepository tenantMembershipRepository = tenantMembershipRepositoryProvider.getIfAvailable();
        var allowedTenants = actor.hasRole("PLATFORM_OWNER") && tenantRepository != null
                ? tenantRepository.findAllByOrderByCreatedAtAsc().stream()
                        .map(tenant -> new AllowedTenantResponse(
                                tenant.getId().toString(),
                                tenant.getName(),
                                tenant.getSlug(),
                                "PLATFORM_OWNER"))
                        .toList()
                : tenantMembershipRepository == null
                        ? java.util.List.<AllowedTenantResponse>of()
                        : tenantMembershipRepository.findByUserExternalSubjectAndStatusOrderByCreatedAtAsc(actor.userId(), "ACTIVE").stream()
                        .map(membership -> new AllowedTenantResponse(
                                membership.getTenant().getId().toString(),
                                membership.getTenant().getName(),
                                membership.getTenant().getSlug(),
                                membership.getRole()))
                        .toList();
        return new AuthContextResponse(
                actor.creator(),
                actor.userId(),
                actor.userId(),
                actor.tenantId() == null ? null : actor.tenantId().toString(),
                actor.tenantName(),
                actor.roles(),
                allowedTenants,
                actor.platformScope(),
                actor.actingAsPlatformOwner(),
                actor.actingAsPlatformOwner(),
                demoStatus == null ? null : demoStatus.planCode(),
                demoStatus == null ? null : demoStatus.demoExpiresAt(),
                demoStatus == null ? null : demoStatus.demoDaysRemaining(),
                demoStatus == null ? null : demoStatus.demoCapabilities(),
                demoStatus == null ? null : demoStatus.demoUsage()
        );
    }
}
