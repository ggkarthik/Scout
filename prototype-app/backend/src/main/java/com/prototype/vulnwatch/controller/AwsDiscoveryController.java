package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.AwsConnectionTestResponse;
import com.prototype.vulnwatch.dto.AwsDiscoveryConfigRequest;
import com.prototype.vulnwatch.dto.AwsDiscoveryConfigResponse;
import com.prototype.vulnwatch.dto.AwsDiscoveryTargetRequest;
import com.prototype.vulnwatch.dto.AwsDiscoveryTargetResponse;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.service.AwsDiscoveryConfigService;
import com.prototype.vulnwatch.service.AwsDiscoverySyncService;
import com.prototype.vulnwatch.service.AwsDiscoveryTargetService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.util.List;
import java.util.UUID;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/connectors/aws-discovery")
public class AwsDiscoveryController {

    private final WorkspaceService workspaceService;
    private final AwsDiscoveryConfigService awsDiscoveryConfigService;
    private final AwsDiscoverySyncService awsDiscoverySyncService;
    private final AwsDiscoveryTargetService awsDiscoveryTargetService;

    public AwsDiscoveryController(
            WorkspaceService workspaceService,
            AwsDiscoveryConfigService awsDiscoveryConfigService,
            AwsDiscoverySyncService awsDiscoverySyncService,
            AwsDiscoveryTargetService awsDiscoveryTargetService
    ) {
        this.workspaceService = workspaceService;
        this.awsDiscoveryConfigService = awsDiscoveryConfigService;
        this.awsDiscoverySyncService = awsDiscoverySyncService;
        this.awsDiscoveryTargetService = awsDiscoveryTargetService;
    }

    /** GET /api/connectors/aws-discovery — returns the current connector config (never null). */
    @GetMapping
    public AwsDiscoveryConfigResponse get() {
        Tenant tenant = workspaceService.getWorkspace();
        return awsDiscoveryConfigService.get(tenant);
    }

    /** PUT /api/connectors/aws-discovery — create or update the connector config. */
    @PutMapping
    public AwsDiscoveryConfigResponse save(@RequestBody AwsDiscoveryConfigRequest request) {
        Tenant tenant = workspaceService.getWorkspace();
        return awsDiscoveryConfigService.save(tenant, request);
    }

    /** POST /api/connectors/aws-discovery/test — test the current connector config. */
    @PostMapping("/test")
    public AwsConnectionTestResponse test() {
        Tenant tenant = workspaceService.getWorkspace();
        return awsDiscoveryConfigService.test(tenant);
    }

    /** POST /api/connectors/aws-discovery/sync — manually trigger a sync run. */
    @PostMapping("/sync")
    public SyncTriggerResponse sync() {
        return awsDiscoverySyncService.trigger();
    }

    @GetMapping("/targets")
    public List<AwsDiscoveryTargetResponse> listTargets() {
        Tenant tenant = workspaceService.getWorkspace();
        return awsDiscoveryTargetService.list(tenant);
    }

    @PostMapping("/targets")
    public AwsDiscoveryTargetResponse createTarget(@RequestBody AwsDiscoveryTargetRequest request) {
        Tenant tenant = workspaceService.getWorkspace();
        return awsDiscoveryTargetService.create(tenant, request);
    }

    @PutMapping("/targets/{targetId}")
    public AwsDiscoveryTargetResponse updateTarget(
            @PathVariable UUID targetId,
            @RequestBody AwsDiscoveryTargetRequest request
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        return awsDiscoveryTargetService.update(tenant, targetId, request);
    }

    @DeleteMapping("/targets/{targetId}")
    public void deleteTarget(@PathVariable UUID targetId) {
        Tenant tenant = workspaceService.getWorkspace();
        awsDiscoveryTargetService.delete(tenant, targetId);
    }

    @PostMapping("/targets/{targetId}/test")
    public AwsConnectionTestResponse testTarget(@PathVariable UUID targetId) {
        Tenant tenant = workspaceService.getWorkspace();
        return awsDiscoveryTargetService.test(tenant, targetId);
    }

    @PostMapping("/targets/{targetId}/sync")
    public SyncTriggerResponse syncTarget(@PathVariable UUID targetId) {
        Tenant tenant = workspaceService.getWorkspace();
        return awsDiscoverySyncService.triggerTarget(tenant, targetId);
    }

    /** GET /api/connectors/aws-discovery/sync/status — check whether a run is active. */
    @GetMapping("/sync/status")
    public AwsSyncStatusResponse syncStatus() {
        boolean active = awsDiscoverySyncService.hasActiveRun();
        return new AwsSyncStatusResponse(active, active ? "running" : "idle");
    }

    public record AwsSyncStatusResponse(boolean active, String status) {}
}
