package com.prototype.vulnwatch.aisecurity.controller;

import com.prototype.vulnwatch.aisecurity.azure.AiSecurityAzureConnectorService;
import com.prototype.vulnwatch.aisecurity.azure.AiSecurityAzureConnectorService.ConnectionTestResponse;
import com.prototype.vulnwatch.aisecurity.azure.AiSecurityAzureConnectorService.ConnectorRequest;
import com.prototype.vulnwatch.aisecurity.azure.AiSecurityAzureConnectorService.ConnectorResponse;
import com.prototype.vulnwatch.aisecurity.azure.AiSecurityAzureCredentialService;
import com.prototype.vulnwatch.aisecurity.azure.AiSecurityAzureCredentialService.CredentialProfileRequest;
import com.prototype.vulnwatch.aisecurity.azure.AiSecurityAzureCredentialService.CredentialProfileResponse;
import com.prototype.vulnwatch.aisecurity.azure.AiSecurityAzureCredentialService.CredentialTestResponse;
import com.prototype.vulnwatch.aisecurity.azure.AiSecurityAzureCredentialService.RotateCredentialRequest;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAccessService;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.IngestionJobAcceptedResponse;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.util.List;
import java.util.UUID;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/connectors/ai-security/azure")
public class AiSecurityAzureConnectorController {

    private final WorkspaceService workspace;
    private final RequestActorService actors;
    private final AiSecurityAccessService access;
    private final AiSecurityAzureConnectorService connectors;
    private final AiSecurityAzureCredentialService credentials;

    public AiSecurityAzureConnectorController(
            WorkspaceService workspace,
            RequestActorService actors,
            AiSecurityAccessService access,
            AiSecurityAzureConnectorService connectors,
            AiSecurityAzureCredentialService credentials
    ) {
        this.workspace = workspace;
        this.actors = actors;
        this.access = access;
        this.connectors = connectors;
        this.credentials = credentials;
    }

    @GetMapping
    public List<ConnectorResponse> list() {
        return connectors.list(tenant());
    }

    @GetMapping("/requirements")
    public com.prototype.vulnwatch.aisecurity.azure.AzurePolicyPermissionMatrix.RequirementsReport requirements() {
        tenant();
        return connectors.requirements();
    }

    @PutMapping
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public ConnectorResponse save(@RequestBody ConnectorRequest request) {
        return connectors.save(tenant(), request);
    }

    @PostMapping("/{connectorId}/test")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public ConnectionTestResponse test(@PathVariable UUID connectorId) {
        return connectors.test(tenant(), connectorId, actor());
    }

    @PostMapping("/{connectorId}/run")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public IngestionJobAcceptedResponse run(@PathVariable UUID connectorId) {
        return connectors.trigger(tenant(), connectorId, actor());
    }

    @PostMapping("/targets/{targetId}/run")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public IngestionJobAcceptedResponse runTarget(@PathVariable UUID targetId) {
        return connectors.triggerTarget(tenant(), targetId, actor());
    }

    @GetMapping("/credentials")
    public List<CredentialProfileResponse> credentialProfiles() {
        return credentials.list(tenant());
    }

    @PostMapping("/credentials")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public CredentialProfileResponse createCredential(@RequestBody CredentialProfileRequest request) {
        return credentials.create(tenant(), request, actor());
    }

    @PostMapping("/credentials/{profileId}/test")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public CredentialTestResponse testCredential(
            @PathVariable UUID profileId,
            @RequestParam String subscriptionId
    ) {
        return credentials.test(tenant(), profileId, subscriptionId, actor());
    }

    @PostMapping("/credentials/{profileId}/rotate")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public CredentialProfileResponse rotateCredential(
            @PathVariable UUID profileId,
            @RequestBody RotateCredentialRequest request
    ) {
        return credentials.rotate(tenant(), profileId, request, actor());
    }

    @DeleteMapping("/credentials/{profileId}")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public void revokeCredential(@PathVariable UUID profileId) {
        credentials.revoke(tenant(), profileId, actor());
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
