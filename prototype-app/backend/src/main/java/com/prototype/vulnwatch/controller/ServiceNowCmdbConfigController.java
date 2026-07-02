package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.ServiceNowCmdbConfigRequest;
import com.prototype.vulnwatch.dto.ServiceNowCmdbConfigResponse;
import com.prototype.vulnwatch.dto.ServiceNowCmdbConnectionTestResponse;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.security.SensitiveTenantAction;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.DemoLifecycleService;
import com.prototype.vulnwatch.service.ServiceNowCmdbConfigService;
import com.prototype.vulnwatch.service.ServiceNowCmdbSyncService;
import com.prototype.vulnwatch.service.WorkspaceService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.access.prepost.PreAuthorize;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/connectors/servicenow-cmdb")
public class ServiceNowCmdbConfigController {
    private static final Logger LOG = LoggerFactory.getLogger(ServiceNowCmdbConfigController.class);

    private final WorkspaceService workspaceService;
    private final ServiceNowCmdbConfigService serviceNowCmdbConfigService;
    private final ServiceNowCmdbSyncService serviceNowCmdbSyncService;
    private final AuditEventService auditEventService;
    private final ObjectProvider<DemoLifecycleService> demoLifecycleServiceProvider;

    public ServiceNowCmdbConfigController(
            WorkspaceService workspaceService,
            ServiceNowCmdbConfigService serviceNowCmdbConfigService,
            ServiceNowCmdbSyncService serviceNowCmdbSyncService,
            AuditEventService auditEventService,
            ObjectProvider<DemoLifecycleService> demoLifecycleServiceProvider
    ) {
        this.workspaceService = workspaceService;
        this.serviceNowCmdbConfigService = serviceNowCmdbConfigService;
        this.serviceNowCmdbSyncService = serviceNowCmdbSyncService;
        this.auditEventService = auditEventService;
        this.demoLifecycleServiceProvider = demoLifecycleServiceProvider;
    }

    @GetMapping
    public ServiceNowCmdbConfigResponse get() {
        Tenant tenant = workspaceService.getWorkspace();
        return serviceNowCmdbConfigService.get(tenant);
    }

    @PutMapping
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','INVENTORY_ADMIN')")
    @SensitiveTenantAction("connector.servicenow_cmdb.saved")
    public ServiceNowCmdbConfigResponse save(@Valid @RequestBody ServiceNowCmdbConfigRequest request) {
        Tenant tenant = workspaceService.getWorkspace();
        assertDemoAllowsLiveConnector(tenant);
        ServiceNowCmdbConfigResponse response = serviceNowCmdbConfigService.save(tenant, request);
        recordAuditSafely("connector.servicenow_cmdb.saved", "connector_config", tenant.getId().toString(), null);
        return response;
    }

    @PostMapping("/test")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','INVENTORY_ADMIN')")
    @SensitiveTenantAction("connector.servicenow_cmdb.tested")
    public ServiceNowCmdbConnectionTestResponse test() {
        Tenant tenant = workspaceService.getWorkspace();
        assertDemoAllowsLiveConnector(tenant);
        ServiceNowCmdbConnectionTestResponse response = serviceNowCmdbConfigService.test(tenant);
        recordAuditSafely("connector.servicenow_cmdb.tested", "connector_config", tenant.getId().toString(),
                "{\"status\":\"" + response.status() + "\"}");
        return response;
    }

    @PostMapping("/sync")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','INVENTORY_ADMIN')")
    @SensitiveTenantAction("connector.servicenow_cmdb.sync_triggered")
    public SyncTriggerResponse sync() {
        Tenant tenant = workspaceService.getWorkspace();
        assertDemoAllowsLiveConnector(tenant);
        SyncTriggerResponse response = serviceNowCmdbSyncService.trigger();
        recordAuditSafely("connector.servicenow_cmdb.sync_triggered", "sync_run",
                response.runId() == null ? null : response.runId().toString(), null);
        return response;
    }

    private void assertDemoAllowsLiveConnector(Tenant tenant) {
        DemoLifecycleService demoLifecycleService = demoLifecycleServiceProvider.getIfAvailable();
        if (demoLifecycleService != null) {
            demoLifecycleService.assertDemoAllowsLiveConnector(tenant);
        }
    }

    private void recordAuditSafely(String action, String targetType, String targetId, String detailsJson) {
        try {
            auditEventService.record(action, targetType, targetId, detailsJson);
        } catch (Exception ex) {
            LOG.warn("Failed to record audit event for {} ({}): {}", action, targetType, ex.getMessage());
        }
    }
}
