package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.AiBomDeploymentState;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.AiBomDeclaredResourceDetailResponse;
import com.prototype.vulnwatch.dto.AiBomDeclaredResourceResponse;
import com.prototype.vulnwatch.dto.AiBomMappingProposalRequest;
import com.prototype.vulnwatch.dto.BomSetupActionResponse;
import com.prototype.vulnwatch.dto.FindingResponse;
import com.prototype.vulnwatch.security.SensitiveTenantAction;
import com.prototype.vulnwatch.service.AiBomDeclaredResourceReadService;
import com.prototype.vulnwatch.service.AiBomResourceMappingService;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.RequestActor;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.WorkspaceService;
import jakarta.validation.Valid;
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

/**
 * Milestone 3 part 5.3: reads and the reviewed-mapping workflow for declared AI-BOM resources.
 * Kept separate from {@link BomController}, which owns ingestion and the software-BOM read
 * surface -- declared resources are a distinct concern with their own authorization shape
 * (proposing a mapping is analyst-reachable; approving or removing one is not).
 */
@RestController
@RequestMapping("/api/bom/declared-resources")
public class AiBomDeclaredResourceController {

    private final WorkspaceService workspaceService;
    private final RequestActorService requestActorService;
    private final AiBomDeclaredResourceReadService readService;
    private final AiBomResourceMappingService mappingService;
    private final AuditEventService auditEventService;

    public AiBomDeclaredResourceController(
            WorkspaceService workspaceService,
            RequestActorService requestActorService,
            AiBomDeclaredResourceReadService readService,
            AiBomResourceMappingService mappingService,
            AuditEventService auditEventService) {
        this.workspaceService = workspaceService;
        this.requestActorService = requestActorService;
        this.readService = readService;
        this.mappingService = mappingService;
        this.auditEventService = auditEventService;
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','CREATOR','OPERATOR')")
    public List<AiBomDeclaredResourceResponse> list(
            @RequestParam(required = false) AiBomDeploymentState deploymentState) {
        Tenant tenant = workspaceService.getWorkspace();
        return readService.list(tenant, deploymentState);
    }

    @GetMapping("/setup-actions")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','CREATOR','OPERATOR')")
    public List<BomSetupActionResponse> listSetupActions() {
        Tenant tenant = workspaceService.getWorkspace();
        return readService.listSetupActions(tenant);
    }

    @GetMapping("/{resourceId}")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','CREATOR','OPERATOR')")
    public AiBomDeclaredResourceDetailResponse getDetail(@PathVariable UUID resourceId) {
        Tenant tenant = workspaceService.getWorkspace();
        return readService.getDetail(tenant, resourceId);
    }

    @GetMapping("/{resourceId}/findings")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','CREATOR','OPERATOR')")
    public List<FindingResponse> getFindingsAffecting(@PathVariable UUID resourceId) {
        Tenant tenant = workspaceService.getWorkspace();
        return readService.findingsAffecting(tenant, resourceId);
    }

    @PostMapping("/{resourceId}/mapping/propose")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','CREATOR')")
    @SensitiveTenantAction("ai_bom.mapping.proposed")
    public AiBomDeclaredResourceResponse proposeMapping(
            @PathVariable UUID resourceId, @Valid @RequestBody AiBomMappingProposalRequest request) {
        Tenant tenant = workspaceService.getWorkspace();
        RequestActor actor = requestActorService.currentActor();
        AiBomDeclaredResourceResponse response =
                mappingService.propose(tenant, resourceId, request.artifactId(), actor.userId());
        auditEventService.record(
                "ai_bom.mapping.proposed", "ai_bom_declared_resource", resourceId.toString(),
                "{\"artifactId\":\"" + request.artifactId() + "\"}");
        return response;
    }

    @PostMapping("/{resourceId}/mapping/approve")
    @PreAuthorize("hasAnyRole('INVENTORY_ADMIN','TENANT_ADMIN','CREATOR')")
    @SensitiveTenantAction("ai_bom.mapping.approved")
    public AiBomDeclaredResourceResponse approveMapping(@PathVariable UUID resourceId) {
        Tenant tenant = workspaceService.getWorkspace();
        RequestActor actor = requestActorService.currentActor();
        AiBomDeclaredResourceResponse response = mappingService.approve(tenant, resourceId, actor.userId());
        auditEventService.record(
                "ai_bom.mapping.approved", "ai_bom_declared_resource", resourceId.toString(), null);
        return response;
    }

    @PostMapping("/{resourceId}/mapping/remove")
    @PreAuthorize("hasAnyRole('INVENTORY_ADMIN','TENANT_ADMIN','CREATOR')")
    @SensitiveTenantAction("ai_bom.mapping.removed")
    public AiBomDeclaredResourceResponse removeMapping(@PathVariable UUID resourceId) {
        Tenant tenant = workspaceService.getWorkspace();
        RequestActor actor = requestActorService.currentActor();
        AiBomDeclaredResourceResponse response = mappingService.remove(tenant, resourceId, actor.userId());
        auditEventService.record(
                "ai_bom.mapping.removed", "ai_bom_declared_resource", resourceId.toString(), null);
        return response;
    }
}
