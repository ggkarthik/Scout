package com.prototype.vulnwatch.aisecurity.controller;

import com.prototype.vulnwatch.aisecurity.service.AiSecurityAccessService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityDigestBaselineService;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.util.List;
import java.util.UUID;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/ai-security/artifacts/{artifactId}/digest-baselines")
public class AiSecurityDigestBaselineController {
    private final WorkspaceService workspace;
    private final AiSecurityAccessService access;
    private final RequestActorService actors;
    private final AiSecurityDigestBaselineService baselines;

    public AiSecurityDigestBaselineController(WorkspaceService workspace, AiSecurityAccessService access,
                                              RequestActorService actors, AiSecurityDigestBaselineService baselines) {
        this.workspace = workspace;
        this.access = access;
        this.actors = actors;
        this.baselines = baselines;
    }

    @GetMapping
    public List<AiSecurityDigestBaselineService.Response> list(@PathVariable UUID artifactId) {
        return baselines.list(tenant(), artifactId);
    }

    @PostMapping("/approve")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public AiSecurityDigestBaselineService.Response approve(@PathVariable UUID artifactId,
            @RequestBody AiSecurityDigestBaselineService.Request request) {
        return baselines.approve(tenant(), artifactId, request, actors.currentActor().userId(), false);
    }

    @PostMapping("/reapprove")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public AiSecurityDigestBaselineService.Response reapprove(@PathVariable UUID artifactId,
            @RequestBody AiSecurityDigestBaselineService.Request request) {
        return baselines.approve(tenant(), artifactId, request, actors.currentActor().userId(), true);
    }

    @PostMapping("/revoke")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public AiSecurityDigestBaselineService.Response revoke(@PathVariable UUID artifactId,
                                                            @RequestParam String digestKind) {
        return baselines.revoke(tenant(), artifactId, digestKind, actors.currentActor().userId());
    }

    private Tenant tenant() {
        Tenant tenant = workspace.getWorkspace();
        access.assertEntitled(tenant);
        return tenant;
    }
}
