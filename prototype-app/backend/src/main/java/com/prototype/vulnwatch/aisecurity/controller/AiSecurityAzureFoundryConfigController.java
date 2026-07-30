package com.prototype.vulnwatch.aisecurity.controller;

import com.prototype.vulnwatch.aisecurity.azure.AiSecurityAzureConnectorService.ConnectionTestResponse;
import com.prototype.vulnwatch.aisecurity.azure.AiSecurityAzureFoundryConfigService;
import com.prototype.vulnwatch.aisecurity.azure.AiSecurityAzureFoundryConfigService.FoundryConfigRequest;
import com.prototype.vulnwatch.aisecurity.azure.AiSecurityAzureFoundryConfigService.FoundryConfigResponse;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAccessService;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.IngestionJobAcceptedResponse;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.WorkspaceService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Single-form Azure AI Security setup: one config, save/test/run. Replaces the multi-step
 * credential-profile + Azure Cloud Discovery target binding flow with one orchestrated action.
 */
@RestController
@RequestMapping("/api/connectors/ai-security/azure-foundry")
public class AiSecurityAzureFoundryConfigController {

    private final WorkspaceService workspace;
    private final RequestActorService actors;
    private final AiSecurityAccessService access;
    private final AiSecurityAzureFoundryConfigService service;

    public AiSecurityAzureFoundryConfigController(
            WorkspaceService workspace,
            RequestActorService actors,
            AiSecurityAccessService access,
            AiSecurityAzureFoundryConfigService service
    ) {
        this.workspace = workspace;
        this.actors = actors;
        this.access = access;
        this.service = service;
    }

    @GetMapping
    public FoundryConfigResponse get() {
        return service.get(tenant());
    }

    @PutMapping
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public FoundryConfigResponse save(@RequestBody FoundryConfigRequest request) {
        return service.save(tenant(), request, actor());
    }

    @PostMapping("/test")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public ConnectionTestResponse test() {
        return service.test(tenant(), actor());
    }

    @PostMapping("/run")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public IngestionJobAcceptedResponse run() {
        return service.run(tenant(), actor());
    }

    private Tenant tenant() {
        Tenant tenant = workspace.getWorkspace();
        access.assertEntitled(tenant);
        return tenant;
    }

    private String actor() {
        return actors.currentActor().userId();
    }
}
