package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.AdvisoryBatchRequest;
import com.prototype.vulnwatch.dto.GithubSbomIngestionRequest;
import com.prototype.vulnwatch.dto.GithubSbomIngestionBatchResponse;
import com.prototype.vulnwatch.dto.IngestionResult;
import com.prototype.vulnwatch.dto.SbomEndpointIngestionRequest;
import com.prototype.vulnwatch.dto.SbomIngestionResponse;
import com.prototype.vulnwatch.dto.SbomUploadEvidenceResponse;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.service.SbomIngestionService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.VulnerabilityIngestionService;
import jakarta.validation.Valid;
import java.io.IOException;
import java.util.List;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api")
public class IngestionController {

    private final TenantService tenantService;
    private final SbomIngestionService sbomIngestionService;
    private final VulnerabilityIngestionService vulnerabilityIngestionService;

    public IngestionController(
            TenantService tenantService,
            SbomIngestionService sbomIngestionService,
            VulnerabilityIngestionService vulnerabilityIngestionService
    ) {
        this.tenantService = tenantService;
        this.sbomIngestionService = sbomIngestionService;
        this.vulnerabilityIngestionService = vulnerabilityIngestionService;
    }

    @PostMapping(value = "/sbom-upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public SbomIngestionResponse uploadSbom(
            @RequestParam("assetType") AssetType assetType,
            @RequestParam("assetName") String assetName,
            @RequestParam("assetIdentifier") String assetIdentifier,
            @RequestParam("file") MultipartFile file
    ) throws IOException {
        Tenant tenant = tenantService.getDefaultTenant();
        return sbomIngestionService.ingest(tenant, assetType, assetName, assetIdentifier, file);
    }

    @PostMapping("/sbom-fetch")
    public SbomIngestionResponse fetchSbomFromEndpoint(
            @Valid @RequestBody SbomEndpointIngestionRequest request
    ) throws IOException {
        Tenant tenant = tenantService.getDefaultTenant();
        return sbomIngestionService.ingestFromEndpoint(tenant, request);
    }

    @PostMapping("/sbom-fetch/github")
    public GithubSbomIngestionBatchResponse fetchSbomFromGithub(
            @Valid @RequestBody GithubSbomIngestionRequest request
    ) throws IOException {
        Tenant tenant = tenantService.getDefaultTenant();
        return sbomIngestionService.ingestFromGithub(tenant, request);
    }

    @GetMapping("/sbom-uploads")
    public List<SbomUploadEvidenceResponse> listSbomUploads() {
        Tenant tenant = tenantService.getDefaultTenant();
        return sbomIngestionService.listUploads(tenant);
    }

    @PostMapping("/ingestion/nvd-sync")
    public SyncTriggerResponse syncNvd(@RequestParam(defaultValue = "24") int lookbackHours) {
        return vulnerabilityIngestionService.triggerNvdSync(lookbackHours);
    }

    @PostMapping("/ingestion/nvd-full-sync")
    public SyncTriggerResponse syncNvdFull() {
        return vulnerabilityIngestionService.triggerNvdFullSync();
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

    @PostMapping("/ingestion/advisories")
    public IngestionResult ingestAdvisories(@Valid @RequestBody AdvisoryBatchRequest request) {
        return vulnerabilityIngestionService.ingestAdvisories(request);
    }

}
