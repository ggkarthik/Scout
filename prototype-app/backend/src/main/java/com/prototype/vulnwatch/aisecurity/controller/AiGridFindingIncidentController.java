package com.prototype.vulnwatch.aisecurity.controller;

import com.prototype.vulnwatch.aisecurity.service.AiSecurityAccessService;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CreateServiceNowIncidentRequest;
import com.prototype.vulnwatch.dto.ServiceNowIncidentResponse;
import com.prototype.vulnwatch.service.ServiceNowIncidentService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.util.UUID;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/findings")
public class AiGridFindingIncidentController {
    private final WorkspaceService workspaces;
    private final AiSecurityAccessService access;
    private final ServiceNowIncidentService incidents;

    public AiGridFindingIncidentController(WorkspaceService workspaces, AiSecurityAccessService access,
                                           ServiceNowIncidentService incidents) {
        this.workspaces = workspaces;
        this.access = access;
        this.incidents = incidents;
    }

    @PostMapping("/{findingId}/servicenow-incident")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public ServiceNowIncidentResponse create(@PathVariable UUID findingId,
                                             @RequestBody CreateServiceNowIncidentRequest request) {
        Tenant tenant = workspaces.getWorkspace();
        access.assertEntitled(tenant);
        return incidents.createFindingIncident(tenant, findingId, request);
    }
}
