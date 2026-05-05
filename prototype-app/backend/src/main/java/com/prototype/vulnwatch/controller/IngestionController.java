package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.AdvisoryBatchRequest;
import com.prototype.vulnwatch.dto.IngestionResult;
import com.prototype.vulnwatch.dto.NvdFullSyncRequest;
import com.prototype.vulnwatch.dto.SbomEndpointIngestionRequest;
import com.prototype.vulnwatch.dto.SbomIngestionResponse;
import com.prototype.vulnwatch.dto.SbomUploadEvidenceResponse;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.dto.VexAssertionRepairSummaryResponse;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.DemoLifecycleService;
import com.prototype.vulnwatch.service.SbomIngestionService;
import com.prototype.vulnwatch.service.VulnerabilityIngestionService;
import com.prototype.vulnwatch.service.WorkspaceService;
import jakarta.validation.Valid;
import java.io.IOException;
import java.util.List;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class IngestionController {

    private final WorkspaceService workspaceService;
    private final SbomIngestionService sbomIngestionService;
    private final VulnerabilityIngestionService vulnerabilityIngestionService;
    private final AuditEventService auditEventService;
    private final ObjectProvider<DemoLifecycleService> demoLifecycleServiceProvider;

    public IngestionController(
            WorkspaceService workspaceService,
            SbomIngestionService sbomIngestionService,
            VulnerabilityIngestionService vulnerabilityIngestionService,
            AuditEventService auditEventService,
            ObjectProvider<DemoLifecycleService> demoLifecycleServiceProvider
    ) {
        this.workspaceService = workspaceService;
        this.sbomIngestionService = sbomIngestionService;
        this.vulnerabilityIngestionService = vulnerabilityIngestionService;
        this.auditEventService = auditEventService;
        this.demoLifecycleServiceProvider = demoLifecycleServiceProvider;
    }

    @PostMapping("/sbom-fetch")
    public SbomIngestionResponse fetchSbomFromEndpoint(
            @Valid @RequestBody SbomEndpointIngestionRequest request
    ) throws IOException {
        Tenant tenant = workspaceService.getWorkspace();
        DemoLifecycleService demoLifecycleService = demoLifecycleServiceProvider.getIfAvailable();
        if (demoLifecycleService != null) {
            demoLifecycleService.assertCanUploadSbom(tenant);
        }
        SbomIngestionResponse response = sbomIngestionService.ingestFromEndpoint(tenant, request);
        auditEventService.record("inventory.sbom.fetch", "sbom_fetch", response.sbomUploadId() == null ? null : response.sbomUploadId().toString(), null);
        return response;
    }

    @GetMapping("/ingestions")
    public List<SbomUploadEvidenceResponse> listIngestions(
            @RequestParam(required = false) String sourceSystem
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        return sbomIngestionService.listUploads(tenant, sourceSystem);
    }

    @PostMapping("/ingestion/nvd-sync")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public SyncTriggerResponse syncNvd(@RequestParam(defaultValue = "24") int lookbackHours) {
        SyncTriggerResponse response = vulnerabilityIngestionService.triggerNvdSync(lookbackHours);
        auditEventService.record("platform.vulnerability_feed.nvd_sync", "sync_run", response.runId() == null ? null : response.runId().toString(),
                "{\"lookbackHours\":" + lookbackHours + "}");
        return response;
    }

    @PostMapping("/ingestion/nvd-full-sync")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public SyncTriggerResponse syncNvdFull(@RequestBody(required = false) NvdFullSyncRequest request) {
        SyncTriggerResponse response = vulnerabilityIngestionService.triggerNvdFullSync(request == null ? null : request.apiKey());
        auditEventService.record("platform.vulnerability_feed.nvd_full_sync", "sync_run", response.runId() == null ? null : response.runId().toString(), null);
        return response;
    }

    @PostMapping("/ingestion/nvd-cve/{cveId}")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public IngestionResult refreshCveFromNvd(@PathVariable String cveId) {
        IngestionResult response = vulnerabilityIngestionService.refreshSingleCveFromNvd(cveId);
        auditEventService.record("platform.vulnerability_feed.nvd_cve_refresh", "vulnerability", cveId, null);
        return response;
    }

    @PostMapping("/ingestion/kev-sync")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public SyncTriggerResponse syncKev() {
        SyncTriggerResponse response = vulnerabilityIngestionService.triggerKevSync();
        auditEventService.record("platform.vulnerability_feed.kev_sync", "sync_run", response.runId() == null ? null : response.runId().toString(), null);
        return response;
    }

    @PostMapping("/ingestion/ghsa-sync")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public SyncTriggerResponse syncGhsa() {
        SyncTriggerResponse response = vulnerabilityIngestionService.triggerGhsaSync();
        auditEventService.record("platform.vulnerability_feed.ghsa_sync", "sync_run", response.runId() == null ? null : response.runId().toString(), null);
        return response;
    }

    @PostMapping("/ingestion/csaf/microsoft-sync")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public SyncTriggerResponse syncMicrosoftCsaf() {
        SyncTriggerResponse response = vulnerabilityIngestionService.triggerMicrosoftCsafSync();
        auditEventService.record("platform.vulnerability_feed.microsoft_csaf_sync", "sync_run", response.runId() == null ? null : response.runId().toString(), null);
        return response;
    }

    @PostMapping("/ingestion/csaf/redhat-sync")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public SyncTriggerResponse syncRedhatCsaf() {
        SyncTriggerResponse response = vulnerabilityIngestionService.triggerRedhatCsafSync();
        auditEventService.record("platform.vulnerability_feed.redhat_csaf_sync", "sync_run", response.runId() == null ? null : response.runId().toString(), null);
        return response;
    }

    @PostMapping("/ingestion/vex-assertion-repair")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public SyncTriggerResponse repairVexAssertions() {
        SyncTriggerResponse response = vulnerabilityIngestionService.triggerVexAssertionRepair();
        auditEventService.record("platform.vulnerability_feed.vex_assertion_repair", "sync_run", response.runId() == null ? null : response.runId().toString(), null);
        return response;
    }

    @PostMapping("/ingestion/vex-rollout-backfill")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public SyncTriggerResponse runVexRolloutBackfill() {
        SyncTriggerResponse response = vulnerabilityIngestionService.triggerVexRolloutBackfill();
        auditEventService.record("platform.vulnerability_feed.vex_rollout_backfill", "sync_run", response.runId() == null ? null : response.runId().toString(), null);
        return response;
    }

    @GetMapping("/ingestion/vex-assertion-repair/summary")
    public VexAssertionRepairSummaryResponse getVexAssertionRepairSummary() {
        return vulnerabilityIngestionService.getVexAssertionRepairSummary();
    }

    @PostMapping("/ingestion/advisories")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public IngestionResult ingestAdvisories(@Valid @RequestBody AdvisoryBatchRequest request) {
        IngestionResult response = vulnerabilityIngestionService.ingestAdvisories(request);
        auditEventService.record("platform.vulnerability_feed.advisory_ingest", "advisory_batch", null, null);
        return response;
    }

}
