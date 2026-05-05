package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.GithubGhcrSbomIngestionRequest;
import com.prototype.vulnwatch.dto.GithubSbomIngestionRequest;
import com.prototype.vulnwatch.dto.GithubSbomSourceRequest;
import com.prototype.vulnwatch.dto.GithubSbomSourceResponse;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.DemoLifecycleService;
import com.prototype.vulnwatch.service.GithubSbomSourceService;
import com.prototype.vulnwatch.service.WorkspaceService;
import jakarta.validation.Valid;
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
@RequestMapping("/api/github-sbom-sources")
public class GithubSbomSourceController {

    private final GithubSbomSourceService githubSbomSourceService;
    private final AuditEventService auditEventService;
    private final WorkspaceService workspaceService;
    private final ObjectProvider<DemoLifecycleService> demoLifecycleServiceProvider;

    public GithubSbomSourceController(
            GithubSbomSourceService githubSbomSourceService,
            AuditEventService auditEventService,
            WorkspaceService workspaceService,
            ObjectProvider<DemoLifecycleService> demoLifecycleServiceProvider
    ) {
        this.githubSbomSourceService = githubSbomSourceService;
        this.auditEventService = auditEventService;
        this.workspaceService = workspaceService;
        this.demoLifecycleServiceProvider = demoLifecycleServiceProvider;
    }

    @GetMapping
    public List<GithubSbomSourceResponse> list() {
        return githubSbomSourceService.list();
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public GithubSbomSourceResponse create(@Valid @RequestBody GithubSbomSourceRequest request) {
        assertDemoAllowsLiveConnector();
        GithubSbomSourceResponse response = githubSbomSourceService.create(request);
        auditEventService.record("connector.github_sbom_source.created", "github_sbom_source", response.id().toString(), null);
        return response;
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public GithubSbomSourceResponse update(@PathVariable UUID id, @Valid @RequestBody GithubSbomSourceRequest request) {
        assertDemoAllowsLiveConnector();
        GithubSbomSourceResponse response = githubSbomSourceService.update(id, request);
        auditEventService.record("connector.github_sbom_source.updated", "github_sbom_source", id.toString(), null);
        return response;
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public void delete(@PathVariable UUID id) {
        assertDemoAllowsLiveConnector();
        githubSbomSourceService.delete(id);
        auditEventService.record("connector.github_sbom_source.deleted", "github_sbom_source", id.toString(), null);
    }

    @PostMapping("/ghcr/run")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public SyncTriggerResponse runGhcrOnce(@Valid @RequestBody GithubGhcrSbomIngestionRequest request) {
        assertDemoAllowsLiveConnector();
        SyncTriggerResponse response = githubSbomSourceService.triggerGhcrRunOnce(request.owner());
        auditEventService.record("connector.github_sbom_source.ghcr_run_triggered", "sync_run",
                response.runId() == null ? null : response.runId().toString(), null);
        return response;
    }

    @PostMapping("/repository/run")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public SyncTriggerResponse runRepositoryOnce(@Valid @RequestBody GithubSbomIngestionRequest request) {
        assertDemoAllowsLiveConnector();
        SyncTriggerResponse response = githubSbomSourceService.triggerRepositoryRunOnce(request);
        auditEventService.record("connector.github_sbom_source.repository_run_triggered", "sync_run",
                response.runId() == null ? null : response.runId().toString(), null);
        return response;
    }

    @PostMapping("/{id}/run")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public SyncTriggerResponse run(@PathVariable UUID id) {
        assertDemoAllowsLiveConnector();
        SyncTriggerResponse response = githubSbomSourceService.trigger(id);
        auditEventService.record("connector.github_sbom_source.run_triggered", "sync_run",
                response.runId() == null ? null : response.runId().toString(), "{\"sourceId\":\"" + id + "\"}");
        return response;
    }

    private void assertDemoAllowsLiveConnector() {
        DemoLifecycleService demoLifecycleService = demoLifecycleServiceProvider.getIfAvailable();
        if (demoLifecycleService != null) {
            demoLifecycleService.assertDemoAllowsLiveConnector(workspaceService.getWorkspace());
        }
    }
}
