package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.SccmCmdbConfigRequest;
import com.prototype.vulnwatch.dto.SccmCmdbConfigResponse;
import com.prototype.vulnwatch.dto.SccmConnectionTestResponse;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.DemoLifecycleService;
import com.prototype.vulnwatch.service.SccmCmdbConfigService;
import com.prototype.vulnwatch.service.SccmCmdbSyncService;
import com.prototype.vulnwatch.service.WorkspaceService;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/connectors/sccm-cmdb")
public class SccmCmdbController {

    private final WorkspaceService workspaceService;
    private final SccmCmdbConfigService sccmCmdbConfigService;
    private final SccmCmdbSyncService sccmCmdbSyncService;
    private final AuditEventService auditEventService;
    private final ObjectProvider<DemoLifecycleService> demoLifecycleServiceProvider;

    public SccmCmdbController(
            WorkspaceService workspaceService,
            SccmCmdbConfigService sccmCmdbConfigService,
            SccmCmdbSyncService sccmCmdbSyncService,
            AuditEventService auditEventService,
            ObjectProvider<DemoLifecycleService> demoLifecycleServiceProvider
    ) {
        this.workspaceService = workspaceService;
        this.sccmCmdbConfigService = sccmCmdbConfigService;
        this.sccmCmdbSyncService = sccmCmdbSyncService;
        this.auditEventService = auditEventService;
        this.demoLifecycleServiceProvider = demoLifecycleServiceProvider;
    }

    /** GET /api/connectors/sccm-cmdb — returns the current connector config (never null). */
    @GetMapping
    public SccmCmdbConfigResponse get() {
        Tenant tenant = workspaceService.getWorkspace();
        return sccmCmdbConfigService.get(tenant);
    }

    /** PUT /api/connectors/sccm-cmdb — create or update the connector config. */
    @PutMapping
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public SccmCmdbConfigResponse save(@RequestBody SccmCmdbConfigRequest request) {
        Tenant tenant = workspaceService.getWorkspace();
        assertDemoAllowsLiveConnector(tenant);
        SccmCmdbConfigResponse response = sccmCmdbConfigService.save(tenant, request);
        auditEventService.record("connector.sccm_cmdb.saved", "connector_config", tenant.getId().toString(), null);
        return response;
    }

    /** POST /api/connectors/sccm-cmdb/test — test the current connector config. */
    @PostMapping("/test")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public SccmConnectionTestResponse test() {
        Tenant tenant = workspaceService.getWorkspace();
        assertDemoAllowsLiveConnector(tenant);
        SccmConnectionTestResponse response = sccmCmdbConfigService.test(tenant);
        auditEventService.record("connector.sccm_cmdb.tested", "connector_config", tenant.getId().toString(),
                "{\"status\":\"" + response.status() + "\"}");
        return response;
    }

    /** POST /api/connectors/sccm-cmdb/sync — manually trigger a sync run. */
    @PostMapping("/sync")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public SyncTriggerResponse sync() {
        Tenant tenant = workspaceService.getWorkspace();
        assertDemoAllowsLiveConnector(tenant);
        SyncTriggerResponse response = sccmCmdbSyncService.trigger();
        auditEventService.record("connector.sccm_cmdb.sync_triggered", "sync_run",
                response.runId() == null ? null : response.runId().toString(), null);
        return response;
    }

    /** GET /api/connectors/sccm-cmdb/sync/status — check whether a run is active. */
    @GetMapping("/sync/status")
    public SccmSyncStatusResponse syncStatus() {
        boolean active = sccmCmdbSyncService.hasActiveRun();
        return new SccmSyncStatusResponse(active, active ? "running" : "idle");
    }

    public record SccmSyncStatusResponse(boolean active, String status) {}

    private void assertDemoAllowsLiveConnector(Tenant tenant) {
        DemoLifecycleService demoLifecycleService = demoLifecycleServiceProvider.getIfAvailable();
        if (demoLifecycleService != null) {
            demoLifecycleService.assertDemoAllowsLiveConnector(tenant);
        }
    }
}
