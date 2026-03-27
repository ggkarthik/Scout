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
import com.prototype.vulnwatch.service.SbomIngestionService;
import com.prototype.vulnwatch.service.VulnerabilityIngestionService;
import com.prototype.vulnwatch.service.WorkspaceService;
import jakarta.validation.Valid;
import java.io.IOException;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
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

    public IngestionController(
            WorkspaceService workspaceService,
            SbomIngestionService sbomIngestionService,
            VulnerabilityIngestionService vulnerabilityIngestionService
    ) {
        this.workspaceService = workspaceService;
        this.sbomIngestionService = sbomIngestionService;
        this.vulnerabilityIngestionService = vulnerabilityIngestionService;
    }

    @PostMapping("/sbom-fetch")
    public SbomIngestionResponse fetchSbomFromEndpoint(
            @Valid @RequestBody SbomEndpointIngestionRequest request
    ) throws IOException {
        Tenant tenant = workspaceService.getWorkspace();
        return sbomIngestionService.ingestFromEndpoint(tenant, request);
    }

    @GetMapping("/ingestions")
    public List<SbomUploadEvidenceResponse> listIngestions(
            @RequestParam(required = false) String sourceSystem
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        return sbomIngestionService.listUploads(tenant, sourceSystem);
    }

    @PostMapping("/ingestion/nvd-sync")
    public SyncTriggerResponse syncNvd(@RequestParam(defaultValue = "24") int lookbackHours) {
        return vulnerabilityIngestionService.triggerNvdSync(lookbackHours);
    }

    @PostMapping("/ingestion/nvd-full-sync")
    public SyncTriggerResponse syncNvdFull(@RequestBody(required = false) NvdFullSyncRequest request) {
        return vulnerabilityIngestionService.triggerNvdFullSync(request == null ? null : request.apiKey());
    }

    @PostMapping("/ingestion/kev-sync")
    public SyncTriggerResponse syncKev() {
        return vulnerabilityIngestionService.triggerKevSync();
    }

    @PostMapping("/ingestion/ghsa-sync")
    public SyncTriggerResponse syncGhsa() {
        return vulnerabilityIngestionService.triggerGhsaSync();
    }

    @PostMapping("/ingestion/csaf/microsoft-sync")
    public SyncTriggerResponse syncMicrosoftCsaf() {
        return vulnerabilityIngestionService.triggerMicrosoftCsafSync();
    }

    @PostMapping("/ingestion/csaf/redhat-sync")
    public SyncTriggerResponse syncRedhatCsaf() {
        return vulnerabilityIngestionService.triggerRedhatCsafSync();
    }

    @PostMapping("/ingestion/vex-assertion-repair")
    public SyncTriggerResponse repairVexAssertions() {
        return vulnerabilityIngestionService.triggerVexAssertionRepair();
    }

    @PostMapping("/ingestion/vex-rollout-backfill")
    public SyncTriggerResponse runVexRolloutBackfill() {
        return vulnerabilityIngestionService.triggerVexRolloutBackfill();
    }

    @GetMapping("/ingestion/vex-assertion-repair/summary")
    public VexAssertionRepairSummaryResponse getVexAssertionRepairSummary() {
        return vulnerabilityIngestionService.getVexAssertionRepairSummary();
    }

    @PostMapping("/ingestion/advisories")
    public IngestionResult ingestAdvisories(@Valid @RequestBody AdvisoryBatchRequest request) {
        return vulnerabilityIngestionService.ingestAdvisories(request);
    }

}
