package com.prototype.vulnwatch.aisecurity.controller;

import com.prototype.vulnwatch.aisecurity.service.AiSecurityAccessService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAwsConnectorService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAwsConnectorService.ConnectionTestResponse;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAwsConnectorService.ConnectorConfigRequest;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAwsConnectorService.ConnectorConfigResponse;
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

@RestController
@RequestMapping("/api/connectors/ai-security/aws")
public class AiSecurityConnectorController {

    private final WorkspaceService workspaceService;
    private final RequestActorService actorService;
    private final AiSecurityAccessService accessService;
    private final AiSecurityAwsConnectorService connectorService;

    public AiSecurityConnectorController(
            WorkspaceService workspaceService,
            RequestActorService actorService,
            AiSecurityAccessService accessService,
            AiSecurityAwsConnectorService connectorService
    ) {
        this.workspaceService = workspaceService;
        this.actorService = actorService;
        this.accessService = accessService;
        this.connectorService = connectorService;
    }

    @GetMapping
    public ConnectorConfigResponse get() {
        return connectorService.get(tenant());
    }

    @PutMapping
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public ConnectorConfigResponse save(@RequestBody ConnectorConfigRequest request) {
        return connectorService.save(tenant(), request);
    }

    @PostMapping("/test")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public ConnectionTestResponse test() {
        return connectorService.test(tenant());
    }

    @PostMapping("/run")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public IngestionJobAcceptedResponse run() {
        return connectorService.trigger(tenant(), actorService.currentActor().userId());
    }

    private Tenant tenant() {
        Tenant tenant = workspaceService.getWorkspace();
        accessService.assertEntitled(tenant);
        return tenant;
    }
}
