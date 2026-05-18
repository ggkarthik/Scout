package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.AwsConnectionTestResponse;
import com.prototype.vulnwatch.dto.AwsDiscoveryConfigRequest;
import com.prototype.vulnwatch.dto.AwsDiscoveryConfigResponse;
import com.prototype.vulnwatch.dto.AwsDiscoveryTargetRequest;
import com.prototype.vulnwatch.dto.AwsDiscoveryTargetResponse;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.security.SensitiveTenantAction;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.AwsDiscoveryConfigService;
import com.prototype.vulnwatch.service.AwsDiscoverySyncService;
import com.prototype.vulnwatch.service.AwsDiscoveryTargetService;
import com.prototype.vulnwatch.service.DemoLifecycleService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.access.prepost.PreAuthorize;
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
    private final AuditEventService auditEventService;
    private final ObjectProvider<DemoLifecycleService> demoLifecycleServiceProvider;

    public AwsDiscoveryController(
            WorkspaceService workspaceService,
            AwsDiscoveryConfigService awsDiscoveryConfigService,
            AwsDiscoverySyncService awsDiscoverySyncService,
            AwsDiscoveryTargetService awsDiscoveryTargetService,
            AuditEventService auditEventService,
            ObjectProvider<DemoLifecycleService> demoLifecycleServiceProvider
    ) {
        this.workspaceService = workspaceService;
        this.awsDiscoveryConfigService = awsDiscoveryConfigService;
        this.awsDiscoverySyncService = awsDiscoverySyncService;
        this.awsDiscoveryTargetService = awsDiscoveryTargetService;
        this.auditEventService = auditEventService;
        this.demoLifecycleServiceProvider = demoLifecycleServiceProvider;
    }

    /** GET /api/connectors/aws-discovery — returns the current connector config (never null). */
    @GetMapping
    public AwsDiscoveryConfigResponse get() {
        Tenant tenant = workspaceService.getWorkspace();
        return awsDiscoveryConfigService.get(tenant);
    }

    /** PUT /api/connectors/aws-discovery — create or update the connector config. */
    @PutMapping
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','INVENTORY_ADMIN')")
    @SensitiveTenantAction("connector.aws_discovery.saved")
    public AwsDiscoveryConfigResponse save(@RequestBody AwsDiscoveryConfigRequest request) {
        Tenant tenant = workspaceService.getWorkspace();
        assertDemoAllowsLiveConnector(tenant);
        AwsDiscoveryConfigResponse response = awsDiscoveryConfigService.save(tenant, request);
        auditEventService.record("connector.aws_discovery.saved", "connector_config", tenant.getId().toString(), null);
        return response;
    }

    /** POST /api/connectors/aws-discovery/test — test the current connector config. */
    @PostMapping("/test")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','INVENTORY_ADMIN')")
    @SensitiveTenantAction("connector.aws_discovery.tested")
    public AwsConnectionTestResponse test() {
        Tenant tenant = workspaceService.getWorkspace();
        assertDemoAllowsLiveConnector(tenant);
        AwsConnectionTestResponse response = awsDiscoveryConfigService.test(tenant);
        auditEventService.record("connector.aws_discovery.tested", "connector_config", tenant.getId().toString(),
                "{\"status\":\"" + response.status() + "\"}");
        return response;
    }

    /** POST /api/connectors/aws-discovery/sync — manually trigger a sync run. */
    @PostMapping("/sync")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','INVENTORY_ADMIN')")
    @SensitiveTenantAction("connector.aws_discovery.sync_triggered")
    public SyncTriggerResponse sync() {
        Tenant tenant = workspaceService.getWorkspace();
        assertDemoAllowsLiveConnector(tenant);
        SyncTriggerResponse response = awsDiscoverySyncService.trigger();
        auditEventService.record("connector.aws_discovery.sync_triggered", "sync_run",
                response.runId() == null ? null : response.runId().toString(), null);
        return response;
    }

    @GetMapping("/targets")
    public List<AwsDiscoveryTargetResponse> listTargets() {
        Tenant tenant = workspaceService.getWorkspace();
        return awsDiscoveryTargetService.list(tenant);
    }

    @PostMapping("/targets")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','INVENTORY_ADMIN')")
    @SensitiveTenantAction("connector.aws_discovery.target_created")
    public AwsDiscoveryTargetResponse createTarget(@RequestBody AwsDiscoveryTargetRequest request) {
        Tenant tenant = workspaceService.getWorkspace();
        assertDemoAllowsLiveConnector(tenant);
        AwsDiscoveryTargetResponse response = awsDiscoveryTargetService.create(tenant, request);
        auditEventService.record("connector.aws_discovery.target_created", "connector_target", response.id().toString(), null);
        return response;
    }

    @PutMapping("/targets/{targetId}")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','INVENTORY_ADMIN')")
    @SensitiveTenantAction("connector.aws_discovery.target_updated")
    public AwsDiscoveryTargetResponse updateTarget(
            @PathVariable UUID targetId,
            @RequestBody AwsDiscoveryTargetRequest request
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        assertDemoAllowsLiveConnector(tenant);
        AwsDiscoveryTargetResponse response = awsDiscoveryTargetService.update(tenant, targetId, request);
        auditEventService.record("connector.aws_discovery.target_updated", "connector_target", targetId.toString(), null);
        return response;
    }

    @DeleteMapping("/targets/{targetId}")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','INVENTORY_ADMIN')")
    @SensitiveTenantAction("connector.aws_discovery.target_deleted")
    public void deleteTarget(@PathVariable UUID targetId) {
        Tenant tenant = workspaceService.getWorkspace();
        assertDemoAllowsLiveConnector(tenant);
        awsDiscoveryTargetService.delete(tenant, targetId);
        auditEventService.record("connector.aws_discovery.target_deleted", "connector_target", targetId.toString(), null);
    }

    @PostMapping("/targets/{targetId}/test")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','INVENTORY_ADMIN')")
    @SensitiveTenantAction("connector.aws_discovery.target_tested")
    public AwsConnectionTestResponse testTarget(@PathVariable UUID targetId) {
        Tenant tenant = workspaceService.getWorkspace();
        assertDemoAllowsLiveConnector(tenant);
        AwsConnectionTestResponse response = awsDiscoveryTargetService.test(tenant, targetId);
        auditEventService.record("connector.aws_discovery.target_tested", "connector_target", targetId.toString(),
                "{\"status\":\"" + response.status() + "\"}");
        return response;
    }

    @PostMapping("/targets/{targetId}/sync")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','INVENTORY_ADMIN')")
    @SensitiveTenantAction("connector.aws_discovery.target_sync_triggered")
    public SyncTriggerResponse syncTarget(@PathVariable UUID targetId) {
        Tenant tenant = workspaceService.getWorkspace();
        assertDemoAllowsLiveConnector(tenant);
        SyncTriggerResponse response = awsDiscoverySyncService.triggerTarget(tenant, targetId);
        auditEventService.record("connector.aws_discovery.target_sync_triggered", "sync_run",
                response.runId() == null ? null : response.runId().toString(), "{\"targetId\":\"" + targetId + "\"}");
        return response;
    }

    /** GET /api/connectors/aws-discovery/sync/status — check whether a run is active. */
    @GetMapping("/sync/status")
    public AwsSyncStatusResponse syncStatus() {
        boolean active = awsDiscoverySyncService.hasActiveRun();
        return new AwsSyncStatusResponse(active, active ? "running" : "idle");
    }

    public record AwsSyncStatusResponse(boolean active, String status) {}

    private void assertDemoAllowsLiveConnector(Tenant tenant) {
        DemoLifecycleService demoLifecycleService = demoLifecycleServiceProvider.getIfAvailable();
        if (demoLifecycleService != null) {
            demoLifecycleService.assertDemoAllowsLiveConnector(tenant);
        }
    }
}
