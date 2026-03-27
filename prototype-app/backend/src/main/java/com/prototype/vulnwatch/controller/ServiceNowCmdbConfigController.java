package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.ServiceNowCmdbConfigRequest;
import com.prototype.vulnwatch.dto.ServiceNowCmdbConfigResponse;
import com.prototype.vulnwatch.dto.ServiceNowCmdbConnectionTestResponse;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.service.ServiceNowCmdbConfigService;
import com.prototype.vulnwatch.service.ServiceNowCmdbSyncService;
import com.prototype.vulnwatch.service.WorkspaceService;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/connectors/servicenow-cmdb")
public class ServiceNowCmdbConfigController {

    private final WorkspaceService workspaceService;
    private final ServiceNowCmdbConfigService serviceNowCmdbConfigService;
    private final ServiceNowCmdbSyncService serviceNowCmdbSyncService;

    public ServiceNowCmdbConfigController(
            WorkspaceService workspaceService,
            ServiceNowCmdbConfigService serviceNowCmdbConfigService,
            ServiceNowCmdbSyncService serviceNowCmdbSyncService
    ) {
        this.workspaceService = workspaceService;
        this.serviceNowCmdbConfigService = serviceNowCmdbConfigService;
        this.serviceNowCmdbSyncService = serviceNowCmdbSyncService;
    }

    @GetMapping
    public ServiceNowCmdbConfigResponse get() {
        Tenant tenant = workspaceService.getWorkspace();
        return serviceNowCmdbConfigService.get(tenant);
    }

    @PutMapping
    public ServiceNowCmdbConfigResponse save(@Valid @RequestBody ServiceNowCmdbConfigRequest request) {
        Tenant tenant = workspaceService.getWorkspace();
        return serviceNowCmdbConfigService.save(tenant, request);
    }

    @PostMapping("/test")
    public ServiceNowCmdbConnectionTestResponse test() {
        Tenant tenant = workspaceService.getWorkspace();
        return serviceNowCmdbConfigService.test(tenant);
    }

    @PostMapping("/sync")
    public SyncTriggerResponse sync() {
        return serviceNowCmdbSyncService.trigger();
    }
}
