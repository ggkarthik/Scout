package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.SbomFormat;
import com.prototype.vulnwatch.domain.SbomIngestionStatus;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.SyncRunResponse;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.repo.SyncRunRepository;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Sort;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class SyncRunHistoryServiceTest {

    @Mock
    private SyncRunRepository syncRunRepository;

    @Mock
    private SbomUploadRepository sbomUploadRepository;

    @Mock
    private TenantService tenantService;

    @Test
    void synthesizesLegacyGithubRepositoryRunsFromUploadEvidence() {
        Tenant tenant = new Tenant();
        tenant.setName("Default Workspace");
        when(tenantService.getDefaultTenant()).thenReturn(tenant);
        when(syncRunRepository.findQueueByStatuses(List.of("queued", "running"))).thenReturn(List.of());
        when(syncRunRepository.findAll(Sort.by(Sort.Direction.DESC, "startedAt"))).thenReturn(List.of());
        List<SbomUpload> uploads = List.of(
                githubGeneratedUpload(
                        "ggkarthik/microservices-demo-app",
                        Instant.parse("2026-03-08T12:15:45Z"),
                        SbomIngestionStatus.SUCCESS,
                        788,
                        0,
                        null),
                githubGeneratedUpload(
                        "ggkarthik/n8n-workflows",
                        Instant.parse("2026-03-08T12:16:22Z"),
                        SbomIngestionStatus.FAILURE,
                        0,
                        0,
                        "GitHub SBOM API request returned 404"));
        when(sbomUploadRepository.findByTenantAndIngestionSourceSystemIgnoreCaseOrderByUploadedAtDesc(tenant, "github"))
                .thenReturn(uploads);

        SyncRunHistoryService service = new SyncRunHistoryService(
                syncRunRepository,
                sbomUploadRepository,
                tenantService,
                new ObjectMapper());

        List<SyncRunResponse> runs = service.list("inventory", 20);

        assertEquals(1, runs.size());
        SyncRunResponse run = runs.get(0);
        assertEquals("GITHUB_REPOSITORY_SBOM", run.syncType());
        assertEquals("INVENTORY", run.runDomain());
        assertEquals("INGESTION", run.runClass());
        assertEquals("partial_success", run.status());
        assertEquals(2, run.recordsFetched());
        assertEquals(788, run.recordsInserted());
        assertEquals(1, run.recordsFailed());
        assertTrue(run.metadataJson().contains("\"legacyReconstructed\":true"));
        assertTrue(run.metadataJson().contains("\"scope\":\"ggkarthik/*\""));
    }

    @Test
    void skipsLegacyGithubRunWhenPersistedSyncRunAlreadyExists() {
        Tenant tenant = new Tenant();
        tenant.setName("Default Workspace");
        SyncRun persistedRun = new SyncRun();
        persistedRun.setSyncType("GITHUB_REPOSITORY_SBOM");
        persistedRun.setStatus("completed");
        persistedRun.setMetadataJson("{\"sourceSystem\":\"github\",\"scope\":\"ggkarthik/microservices-demo-app\"}");
        ReflectionTestUtils.setField(persistedRun, "startedAt", Instant.parse("2026-03-08T12:15:40Z"));
        persistedRun.setCompletedAt(Instant.parse("2026-03-08T12:16:30Z"));

        when(tenantService.getDefaultTenant()).thenReturn(tenant);
        when(syncRunRepository.findQueueByStatuses(List.of("queued", "running"))).thenReturn(List.of());
        when(syncRunRepository.findAll(Sort.by(Sort.Direction.DESC, "startedAt"))).thenReturn(List.of(persistedRun));
        when(sbomUploadRepository.findByTenantAndIngestionSourceSystemIgnoreCaseOrderByUploadedAtDesc(tenant, "github"))
                .thenReturn(List.of(
                        githubGeneratedUpload(
                                "ggkarthik/microservices-demo-app",
                                Instant.parse("2026-03-08T12:15:45Z"),
                                SbomIngestionStatus.SUCCESS,
                                788,
                                0,
                                null)));

        SyncRunHistoryService service = new SyncRunHistoryService(
                syncRunRepository,
                sbomUploadRepository,
                tenantService,
                new ObjectMapper());

        List<SyncRunResponse> runs = service.list("inventory", 20);

        assertEquals(1, runs.size());
        assertEquals(persistedRun.getStartedAt(), runs.get(0).startedAt());
        assertEquals("GITHUB_REPOSITORY_SBOM", runs.get(0).syncType());
        assertEquals("INVENTORY", runs.get(0).runDomain());
        assertTrue(runs.get(0).metadataJson().contains("microservices-demo-app"));
    }

    @Test
    void separatesProcessingRunsFromVulnIntelFeedRuns() {
        SyncRun feedRun = syncRun("CSAF_MICROSOFT", "completed", Instant.parse("2026-03-15T12:15:00Z"));
        SyncRun processingRun = syncRun("VEX_ROLLOUT_BACKFILL", "running", Instant.parse("2026-03-15T12:16:00Z"));

        when(syncRunRepository.findQueueByStatuses(List.of("queued", "running"))).thenReturn(List.of(processingRun));
        when(syncRunRepository.findAll(Sort.by(Sort.Direction.DESC, "startedAt"))).thenReturn(List.of(processingRun, feedRun));

        SyncRunHistoryService service = new SyncRunHistoryService(
                syncRunRepository,
                sbomUploadRepository,
                tenantService,
                new ObjectMapper());

        List<SyncRunResponse> processingRuns = service.list("processing", 20);
        List<SyncRunResponse> feedRuns = service.list("vuln-intel", 20);
        List<SyncRunResponse> legacyVulnerabilityRuns = service.list("vulnerability", 20);

        assertEquals(1, processingRuns.size());
        assertEquals("VEX_ROLLOUT_BACKFILL", processingRuns.get(0).syncType());
        assertEquals("PROCESSING", processingRuns.get(0).runDomain());
        assertEquals("BACKFILL", processingRuns.get(0).runClass());

        assertEquals(1, feedRuns.size());
        assertEquals("CSAF_MICROSOFT", feedRuns.get(0).syncType());
        assertEquals("VULN_INTEL", feedRuns.get(0).runDomain());
        assertEquals("INGESTION", feedRuns.get(0).runClass());

        assertEquals(2, legacyVulnerabilityRuns.size());
    }

    private SbomUpload githubGeneratedUpload(
            String reference,
            Instant uploadedAt,
            SbomIngestionStatus status,
            int components,
            int findings,
            String errorMessage
    ) {
        SbomUpload upload = new SbomUpload();
        Asset asset = new Asset();
        asset.setType(AssetType.APPLICATION);
        asset.setName(reference);
        asset.setIdentifier("github:" + reference.toLowerCase());
        upload.setAsset(asset);
        upload.setFormat(status == SbomIngestionStatus.SUCCESS ? SbomFormat.SPDX : SbomFormat.UNKNOWN);
        upload.setStatus(status);
        upload.setOriginalFilename("github-generated-sbom.json");
        upload.setIngestionSourceType("GITHUB_GENERATED");
        upload.setIngestionSourceSystem("github");
        upload.setSourceReference(reference);
        upload.setComponentCount(components);
        upload.setFindingsGenerated(findings);
        String[] parts = reference.split("/", 2);
        String evidence = errorMessage == null
                ? "{\"ingestionMode\":\"github-generated\",\"owner\":\"" + parts[0] + "\",\"repo\":\"" + parts[1] + "\"}"
                : "{\"ingestionMode\":\"github-generated\",\"owner\":\"" + parts[0] + "\",\"repo\":\"" + parts[1]
                        + "\",\"errorMessage\":\"" + errorMessage + "\"}";
        upload.setEvidenceJson(evidence);
        ReflectionTestUtils.setField(upload, "uploadedAt", uploadedAt);
        return upload;
    }

    private SyncRun syncRun(String type, String status, Instant startedAt) {
        SyncRun run = new SyncRun();
        ReflectionTestUtils.setField(run, "id", UUID.randomUUID());
        run.setSyncType(type);
        run.setStatus(status);
        ReflectionTestUtils.setField(run, "startedAt", startedAt);
        run.setCompletedAt(startedAt.plusSeconds(30));
        return run;
    }
}
