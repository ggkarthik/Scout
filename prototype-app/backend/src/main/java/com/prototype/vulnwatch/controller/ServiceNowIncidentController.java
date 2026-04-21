package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CreateServiceNowIncidentRequest;
import com.prototype.vulnwatch.dto.ServiceNowIncidentResponse;
import com.prototype.vulnwatch.service.ServiceNowIncidentService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.util.List;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/cve-detail")
public class ServiceNowIncidentController {

    private final WorkspaceService workspaceService;
    private final ServiceNowIncidentService serviceNowIncidentService;

    public ServiceNowIncidentController(
            WorkspaceService workspaceService,
            ServiceNowIncidentService serviceNowIncidentService
    ) {
        this.workspaceService = workspaceService;
        this.serviceNowIncidentService = serviceNowIncidentService;
    }

    /**
     * GET /api/cve-detail/servicenow/assignment-groups
     * Returns the list of active assignment group names from ServiceNow's sys_user_group table.
     */
    @GetMapping("/servicenow/assignment-groups")
    public List<String> listAssignmentGroups() {
        Tenant tenant = workspaceService.getWorkspace();
        return serviceNowIncidentService.listAssignmentGroups(tenant);
    }

    /**
     * POST /api/cve-detail/{cveId}/servicenow-incident
     * Creates one or more ServiceNow incidents for the given CVE, grouped by assignment group
     * (case a) or by software package with a default assignment group (case b).
     */
    @PostMapping("/{cveId}/servicenow-incident")
    public ResponseEntity<List<ServiceNowIncidentResponse>> createIncident(
            @PathVariable String cveId,
            @RequestBody CreateServiceNowIncidentRequest request
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        List<ServiceNowIncidentResponse> responses = serviceNowIncidentService.createIncidents(tenant, cveId, request);
        return ResponseEntity.ok(responses);
    }
}
