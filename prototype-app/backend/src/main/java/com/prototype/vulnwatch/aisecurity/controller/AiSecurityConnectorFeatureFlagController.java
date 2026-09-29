package com.prototype.vulnwatch.aisecurity.controller;

import com.prototype.vulnwatch.aisecurity.service.AiSecurityAccessService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityConnectorFeatureFlagService;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.util.List;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/connectors/ai-security/feature-flags")
public class AiSecurityConnectorFeatureFlagController {
    private final WorkspaceService workspace; private final AiSecurityAccessService access;
    private final RequestActorService actors; private final AiSecurityConnectorFeatureFlagService flags;
    public AiSecurityConnectorFeatureFlagController(WorkspaceService workspace, AiSecurityAccessService access,
            RequestActorService actors, AiSecurityConnectorFeatureFlagService flags) {
        this.workspace=workspace; this.access=access; this.actors=actors; this.flags=flags;
    }
    @GetMapping public List<AiSecurityConnectorFeatureFlagService.Response> list() { return flags.list(tenant()); }
    @PutMapping("/{feature}") @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public AiSecurityConnectorFeatureFlagService.Response update(@PathVariable AiSecurityConnectorFeatureFlagService.Feature feature,
            @RequestBody AiSecurityConnectorFeatureFlagService.Request request) {
        return flags.update(tenant(), feature, request, actors.currentActor().userId());
    }
    private Tenant tenant() { Tenant tenant=workspace.getWorkspace(); access.assertEntitled(tenant); return tenant; }
}
