package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.ServiceNowCmdbConfigRequest;
import com.prototype.vulnwatch.dto.ServiceNowCmdbConfigResponse;
import com.prototype.vulnwatch.dto.ServiceNowCmdbConnectionTestResponse;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.ServiceNowCmdbConfigService;
import com.prototype.vulnwatch.service.ServiceNowCmdbSyncService;
import com.prototype.vulnwatch.service.WorkspaceService;
import jakarta.validation.Valid;
import org.springframework.security.access.prepost.PreAuthorize;
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
    private final AuditEventService auditEventService;

    public ServiceNowCmdbConfigController(
            WorkspaceService workspaceService,
            ServiceNowCmdbConfigService serviceNowCmdbConfigService,
            ServiceNowCmdbSyncService serviceNowCmdbSyncService,
            AuditEventService auditEventService
    ) {
        this.workspaceService = workspaceService;
        this.serviceNowCmdbConfigService = serviceNowCmdbConfigService;
        this.serviceNowCmdbSyncService = serviceNowCmdbSyncService;
        this.auditEventService = auditEventService;
    }

    @GetMapping
    public ServiceNowCmdbConfigResponse get() {
        Tenant tenant = workspaceService.getWorkspace();
        return serviceNowCmdbConfigService.get(tenant);
    }

    @PutMapping
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public ServiceNowCmdbConfigResponse save(@Valid @RequestBody ServiceNowCmdbConfigRequest request) {
        Tenant tenant = workspaceService.getWorkspace();
        ServiceNowCmdbConfigResponse response = serviceNowCmdbConfigService.save(tenant, request);
        auditEventService.record("connector.servicenow_cmdb.saved", "connector_config", tenant.getId().toString(), null);
        return response;
    }

    @PostMapping("/test")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public ServiceNowCmdbConnectionTestResponse test() {
        Tenant tenant = workspaceService.getWorkspace();
        ServiceNowCmdbConnectionTestResponse response = serviceNowCmdbConfigService.test(tenant);
        auditEventService.record("connector.servicenow_cmdb.tested", "connector_config", tenant.getId().toString(),
                "{\"status\":\"" + response.status() + "\"}");
        return response;
    }

    @PostMapping("/sync")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public SyncTriggerResponse sync() {
        SyncTriggerResponse response = serviceNowCmdbSyncService.trigger();
        auditEventService.record("connector.servicenow_cmdb.sync_triggered", "sync_run", response.runId() == null ? null : response.runId().toString(), null);
        return response;
    }
}
