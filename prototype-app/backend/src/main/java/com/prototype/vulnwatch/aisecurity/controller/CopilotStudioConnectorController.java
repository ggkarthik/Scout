package com.prototype.vulnwatch.aisecurity.controller;

import com.prototype.vulnwatch.aisecurity.copilot.CopilotStudioConnectorService;
import com.prototype.vulnwatch.aisecurity.copilot.CopilotStudioDiscoveryService;
import com.prototype.vulnwatch.aisecurity.copilot.CopilotStudioRuntimeCollectionService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAccessService;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.util.List;
import java.util.UUID;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/connectors/ai-security/copilot-studio")
public class CopilotStudioConnectorController {
    private final WorkspaceService workspace;
    private final AiSecurityAccessService access;
    private final CopilotStudioConnectorService service;
    private final CopilotStudioDiscoveryService discovery;
    private final CopilotStudioRuntimeCollectionService runtime;
    public CopilotStudioConnectorController(WorkspaceService workspace, AiSecurityAccessService access, CopilotStudioConnectorService service, CopilotStudioDiscoveryService discovery, CopilotStudioRuntimeCollectionService runtime) {
        this.workspace = workspace; this.access = access; this.service = service; this.discovery = discovery; this.runtime = runtime;
    }
    @GetMapping public List<CopilotStudioConnectorService.Response> list() { return service.list(tenant()); }
    @PutMapping @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public CopilotStudioConnectorService.Response save(@RequestBody CopilotStudioConnectorService.Request request) { return service.save(tenant(), request); }
    @PostMapping("/{connectorId}/run") @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public CopilotStudioDiscoveryService.Result run(@PathVariable UUID connectorId) { return discovery.run(tenant(), connectorId); }
    @PostMapping("/{connectorId}/test") @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public com.prototype.vulnwatch.aisecurity.copilot.CopilotStudioDataverseClient.PermissionTest test(@PathVariable UUID connectorId) { return discovery.test(tenant(), connectorId); }
    @PostMapping("/{connectorId}/runtime-run") @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public CopilotStudioRuntimeCollectionService.Result runtimeRun(@PathVariable UUID connectorId) { return runtime.run(tenant(), connectorId); }
    private Tenant tenant() { Tenant tenant = workspace.getWorkspace(); access.assertEntitled(tenant); return tenant; }
}
