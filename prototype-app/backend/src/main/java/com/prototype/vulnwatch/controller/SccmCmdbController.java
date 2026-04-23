package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.SccmCmdbConfigRequest;
import com.prototype.vulnwatch.dto.SccmCmdbConfigResponse;
import com.prototype.vulnwatch.dto.SccmConnectionTestResponse;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.service.SccmCmdbConfigService;
import com.prototype.vulnwatch.service.SccmCmdbSyncService;
import com.prototype.vulnwatch.service.WorkspaceService;
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

    public SccmCmdbController(
            WorkspaceService workspaceService,
            SccmCmdbConfigService sccmCmdbConfigService,
            SccmCmdbSyncService sccmCmdbSyncService
    ) {
        this.workspaceService = workspaceService;
        this.sccmCmdbConfigService = sccmCmdbConfigService;
        this.sccmCmdbSyncService = sccmCmdbSyncService;
    }

    /** GET /api/connectors/sccm-cmdb — returns the current connector config (never null). */
    @GetMapping
    public SccmCmdbConfigResponse get() {
        Tenant tenant = workspaceService.getWorkspace();
        return sccmCmdbConfigService.get(tenant);
    }

    /** PUT /api/connectors/sccm-cmdb — create or update the connector config. */
    @PutMapping
    public SccmCmdbConfigResponse save(@RequestBody SccmCmdbConfigRequest request) {
        Tenant tenant = workspaceService.getWorkspace();
        return sccmCmdbConfigService.save(tenant, request);
    }

    /** POST /api/connectors/sccm-cmdb/test — test the current connector config. */
    @PostMapping("/test")
    public SccmConnectionTestResponse test() {
        Tenant tenant = workspaceService.getWorkspace();
        return sccmCmdbConfigService.test(tenant);
    }

    /** POST /api/connectors/sccm-cmdb/sync — manually trigger a sync run. */
    @PostMapping("/sync")
    public SyncTriggerResponse sync() {
        return sccmCmdbSyncService.trigger();
    }

    /** GET /api/connectors/sccm-cmdb/sync/status — check whether a run is active. */
    @GetMapping("/sync/status")
    public SccmSyncStatusResponse syncStatus() {
        boolean active = sccmCmdbSyncService.hasActiveRun();
        return new SccmSyncStatusResponse(active, active ? "running" : "idle");
    }

    public record SccmSyncStatusResponse(boolean active, String status) {}
}
