package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.doAnswer;
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
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
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

    @Mock
    private RequestActorService requestActorService;

    @Mock
    private WorkspaceService workspaceService;

    @Mock
    private TenantSchemaExecutionService tenantSchemaExecutionService;

    @Test
    void backfillsLegacyGithubRepositoryRunsAndHistoryReadsPersistedRecords() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Default Workspace");
        when(tenantService.listTenants()).thenReturn(List.of(tenant));
        doAnswer(invocation -> invocation.<java.util.function.Supplier<?>>getArgument(1).get())
                .when(tenantSchemaExecutionService)
                .run(any(Tenant.class), any(java.util.function.Supplier.class));
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
        when(sbomUploadRepository.findByIngestionSourceSystemIgnoreCaseOrderByUploadedAtDesc("github"))
                .thenReturn(uploads);

        AtomicReference<List<SyncRun>> savedRuns = new AtomicReference<>(List.of());
        when(syncRunRepository.saveAll(any())).thenAnswer(invocation -> {
            @SuppressWarnings("unchecked")
            List<SyncRun> runs = new ArrayList<>((List<SyncRun>) invocation.getArgument(0));
            savedRuns.set(runs);
            return runs;
        });

        LegacyGithubSyncRunBackfillService backfillService = new LegacyGithubSyncRunBackfillService(
                syncRunRepository,
                sbomUploadRepository,
                tenantService,
                tenantSchemaExecutionService,
                new ObjectMapper(),
                false
        );

        assertEquals(1, backfillService.backfillMissingRuns());
        when(requestActorService.currentActor()).thenReturn(new RequestActor("tenant-user", false, tenant.getId(), tenant.getName()));
        when(syncRunRepository.findQueueByTenantAndStatuses(tenant.getId(), List.of("queued", "running"))).thenReturn(List.of());
        when(syncRunRepository.findByTenant_IdOrderByStartedAtDesc(tenant.getId())).thenReturn(savedRuns.get());

        SyncRunHistoryService historyService = newHistoryService(tenant);
        List<SyncRunResponse> runs = historyService.list("inventory", 20);

        assertEquals(1, runs.size());
        SyncRunResponse run = runs.get(0);
        assertEquals("GITHUB_REPOSITORY_SBOM", run.syncType());
        assertEquals("INVENTORY", run.runDomain());
        assertEquals("INGESTION", run.runClass());
        assertEquals("partial_success", run.status());
        assertEquals(2, run.recordsFetched());
        assertEquals(788, run.recordsInserted());
        assertEquals(0, run.recordsUpdated());
        assertEquals(1, run.recordsFailed());
        assertTrue(run.metadataJson().contains("\"legacyReconstructed\":true"));
        assertTrue(run.metadataJson().contains("\"scope\":\"ggkarthik/*\""));
    }

    @Test
    void skipsLegacyGithubBackfillWhenPersistedSyncRunAlreadyExists() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Default Workspace");
        SyncRun persistedRun = new SyncRun();
        persistedRun.setSyncType("GITHUB_REPOSITORY_SBOM");
        persistedRun.setStatus("completed");
        persistedRun.setMetadataJson("{\"sourceSystem\":\"github\",\"scope\":\"ggkarthik/microservices-demo-app\"}");
        persistedRun.setStartedAt(Instant.parse("2026-03-08T12:15:40Z"));
        persistedRun.setCompletedAt(Instant.parse("2026-03-08T12:16:30Z"));

        when(tenantService.listTenants()).thenReturn(List.of(tenant));
        doAnswer(invocation -> invocation.<java.util.function.Supplier<?>>getArgument(1).get())
                .when(tenantSchemaExecutionService)
                .run(any(Tenant.class), any(java.util.function.Supplier.class));
        when(syncRunRepository.findAll(Sort.by(Sort.Direction.DESC, "startedAt"))).thenReturn(List.of(persistedRun));
        when(sbomUploadRepository.findByIngestionSourceSystemIgnoreCaseOrderByUploadedAtDesc("github"))
                .thenReturn(List.of(
                        githubGeneratedUpload(
                                "ggkarthik/microservices-demo-app",
                                Instant.parse("2026-03-08T12:15:45Z"),
                                SbomIngestionStatus.SUCCESS,
                                788,
                                0,
                                null)));

        LegacyGithubSyncRunBackfillService backfillService = new LegacyGithubSyncRunBackfillService(
                syncRunRepository,
                sbomUploadRepository,
                tenantService,
                tenantSchemaExecutionService,
                new ObjectMapper(),
                false
        );

        assertEquals(0, backfillService.backfillMissingRuns());
        verify(syncRunRepository, never()).saveAll(any());

        when(requestActorService.currentActor()).thenReturn(new RequestActor("tenant-user", false, tenant.getId(), tenant.getName()));
        when(syncRunRepository.findQueueByTenantAndStatuses(tenant.getId(), List.of("queued", "running"))).thenReturn(List.of());
        when(syncRunRepository.findByTenant_IdOrderByStartedAtDesc(tenant.getId())).thenReturn(List.of(persistedRun));
        SyncRunHistoryService historyService = newHistoryService(tenant);
        List<SyncRunResponse> runs = historyService.list("inventory", 20);

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

        when(requestActorService.currentActor()).thenReturn(new RequestActor("platform-owner", false, null, null, java.util.Set.of("PLATFORM_OWNER")));
        when(syncRunRepository.findByRunScope("PLATFORM_VULNERABILITY", Sort.by(Sort.Direction.ASC, "startedAt"))).thenReturn(List.of(processingRun));
        when(syncRunRepository.findByRunScope("PLATFORM_VULNERABILITY", Sort.by(Sort.Direction.DESC, "startedAt"))).thenReturn(List.of(processingRun, feedRun));

        SyncRunHistoryService service = newHistoryService(defaultWorkspace());

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

    @Test
    void classifiesManualEolConnectorRunsAsVulnIntelButKeepsDateSweepAsProcessing() {
        SyncRun eolConnectorRun = syncRun("EOL_FULL_REFRESH", "queued", Instant.parse("2026-03-15T12:18:00Z"));
        SyncRun eolDateSweepRun = syncRun("EOL_DATE_SWEEP", "completed", Instant.parse("2026-03-15T12:17:00Z"));

        when(requestActorService.currentActor()).thenReturn(new RequestActor("platform-owner", false, null, null, java.util.Set.of("PLATFORM_OWNER")));
        when(syncRunRepository.findByRunScope("PLATFORM_VULNERABILITY", Sort.by(Sort.Direction.ASC, "startedAt")))
                .thenReturn(List.of(eolConnectorRun));
        when(syncRunRepository.findByRunScope("PLATFORM_VULNERABILITY", Sort.by(Sort.Direction.DESC, "startedAt")))
                .thenReturn(List.of(eolConnectorRun, eolDateSweepRun));

        SyncRunHistoryService service = newHistoryService(defaultWorkspace());

        List<SyncRunResponse> vulnIntelRuns = service.list("vuln-intel", 20);
        List<SyncRunResponse> processingRuns = service.list("processing", 20);

        assertEquals(1, vulnIntelRuns.size());
        assertEquals("EOL_FULL_REFRESH", vulnIntelRuns.get(0).syncType());
        assertEquals("VULN_INTEL", vulnIntelRuns.get(0).runDomain());
        assertEquals("INGESTION", vulnIntelRuns.get(0).runClass());

        assertEquals(1, processingRuns.size());
        assertEquals("EOL_DATE_SWEEP", processingRuns.get(0).syncType());
        assertEquals("PROCESSING", processingRuns.get(0).runDomain());
    }

    @Test
    void tenantScopedActorsOnlySeeInventoryRuns() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Default Workspace");

        SyncRun inventoryRun = syncRun("SERVICENOW_CMDB", "completed", Instant.parse("2026-03-15T12:15:00Z"));
        SyncRun vulnIntelRun = syncRun("GHSA", "completed", Instant.parse("2026-03-15T12:16:00Z"));
        SyncRun processingRun = syncRun("VEX_ROLLOUT_BACKFILL", "running", Instant.parse("2026-03-15T12:17:00Z"));

        when(requestActorService.currentActor()).thenReturn(new RequestActor("tenant-admin", false, tenant.getId(), tenant.getName(), java.util.Set.of("TENANT_ADMIN")));
        when(syncRunRepository.findByTenant_IdOrderByStartedAtDesc(tenant.getId())).thenReturn(List.of(processingRun, vulnIntelRun, inventoryRun));
        when(syncRunRepository.findQueueByTenantAndStatuses(tenant.getId(), List.of("queued", "running"))).thenReturn(List.of(processingRun));

        SyncRunHistoryService service = newHistoryService(tenant);

        List<SyncRunResponse> allRuns = service.list("all", 20);
        List<SyncRunResponse> inventoryRuns = service.list("inventory", 20);
        List<SyncRunResponse> vulnerabilityRuns = service.list("vulnerability", 20);
        List<SyncRunResponse> processingRuns = service.list("processing", 20);

        assertEquals(1, allRuns.size());
        assertEquals("SERVICENOW_CMDB", allRuns.get(0).syncType());
        assertEquals(1, inventoryRuns.size());
        assertEquals("SERVICENOW_CMDB", inventoryRuns.get(0).syncType());
        assertTrue(vulnerabilityRuns.isEmpty());
        assertTrue(processingRuns.isEmpty());
        assertFalse(allRuns.stream().anyMatch(run -> "GHSA".equals(run.syncType())));
        assertFalse(allRuns.stream().anyMatch(run -> "VEX_ROLLOUT_BACKFILL".equals(run.syncType())));
    }

    @Test
    void tenantScopedActorsDoNotSeeOtherTenantInventoryRunsInHistoryOrSummary() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Acme");

        SyncRun ownInventoryRun = syncRun("SERVICENOW_CMDB", "completed", Instant.parse("2026-03-15T12:15:00Z"));
        when(requestActorService.currentActor()).thenReturn(new RequestActor("tenant-admin", false, tenant.getId(), tenant.getName(), java.util.Set.of("TENANT_ADMIN")));
        when(syncRunRepository.findByTenant_IdOrderByStartedAtDesc(tenant.getId())).thenReturn(List.of(ownInventoryRun));
        when(syncRunRepository.findQueueByTenantAndStatuses(tenant.getId(), List.of("queued", "running"))).thenReturn(List.of());
        SyncRunHistoryService service = newHistoryService(tenant);

        List<SyncRunResponse> inventoryRuns = service.list("inventory", 20);
        var summary = service.sourcesSummary();

        assertEquals(1, inventoryRuns.size());
        assertEquals("SERVICENOW_CMDB", inventoryRuns.get(0).syncType());
        assertEquals("never", summary.sources().get("GHSA").status());
        verify(syncRunRepository, never()).findAllByOrderByStartedAtDesc();
        verify(syncRunRepository, never()).findQueueByStatuses(List.of("queued", "running"));
        verify(syncRunRepository, never()).findTopBySyncTypeIgnoreCaseOrderByStartedAtDesc("SERVICENOW_CMDB");
    }

    @Test
    void platformOwnersInTenantContextStillSeePlatformVulnerabilityRunHistory() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Acme Security");

        SyncRun platformFeedRun = syncRun("GHSA", "completed", Instant.parse("2026-03-15T12:16:00Z"));
        platformFeedRun.setRunScope("PLATFORM_VULNERABILITY");
        SyncRun platformProcessingRun = syncRun("VEX_ROLLOUT_BACKFILL", "running", Instant.parse("2026-03-15T12:17:00Z"));
        platformProcessingRun.setRunScope("PLATFORM_VULNERABILITY");
        SyncRun tenantInventoryRun = syncRun("SERVICENOW_CMDB", "completed", Instant.parse("2026-03-15T12:15:00Z"));

        when(requestActorService.currentActor()).thenReturn(new RequestActor(
                "platform-owner",
                false,
                tenant.getId(),
                tenant.getName(),
                java.util.Set.of("PLATFORM_OWNER")));
        when(syncRunRepository.findByRunScope("PLATFORM_VULNERABILITY", Sort.by(Sort.Direction.DESC, "startedAt")))
                .thenReturn(List.of(platformProcessingRun, platformFeedRun));
        when(syncRunRepository.findByRunScope("PLATFORM_VULNERABILITY", Sort.by(Sort.Direction.ASC, "startedAt")))
                .thenReturn(List.of(platformProcessingRun));
        when(syncRunRepository.findByTenant_IdOrderByStartedAtDesc(tenant.getId())).thenReturn(List.of(tenantInventoryRun));
        when(syncRunRepository.findQueueByTenantAndStatuses(tenant.getId(), List.of("queued", "running"))).thenReturn(List.of());
        SyncRunHistoryService service = newHistoryService(tenant);

        List<SyncRunResponse> vulnerabilityRuns = service.list("vuln-intel", 20);
        List<SyncRunResponse> processingRuns = service.list("processing", 20);
        List<SyncRunResponse> inventoryRuns = service.list("inventory", 20);
        var summary = service.sourcesSummary();

        assertEquals(1, vulnerabilityRuns.size());
        assertEquals("GHSA", vulnerabilityRuns.get(0).syncType());
        assertEquals("VULN_INTEL", vulnerabilityRuns.get(0).runDomain());

        assertEquals(1, processingRuns.size());
        assertEquals("VEX_ROLLOUT_BACKFILL", processingRuns.get(0).syncType());
        assertEquals("PROCESSING", processingRuns.get(0).runDomain());

        assertEquals(1, inventoryRuns.size());
        assertEquals("SERVICENOW_CMDB", inventoryRuns.get(0).syncType());

        assertEquals("completed", summary.sources().get("GHSA").status());
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
        run.setStartedAt(startedAt);
        run.setCompletedAt(startedAt.plusSeconds(30));
        return run;
    }

    private SyncRunHistoryService newHistoryService(Tenant defaultWorkspace) {
        org.mockito.Mockito.lenient()
                .when(workspaceService.getPlatformWorkspace(WorkspaceService.PlatformWorkspaceUseCase.PLATFORM_VULNERABILITY_RUN_HISTORY))
                .thenReturn(defaultWorkspace);
        org.mockito.Mockito.lenient().doAnswer(invocation -> invocation.<java.util.function.Supplier<?>>getArgument(1).get())
                .when(tenantSchemaExecutionService)
                .run(any(Tenant.class), any(java.util.function.Supplier.class));
        return new SyncRunHistoryService(syncRunRepository, requestActorService, workspaceService, tenantSchemaExecutionService);
    }

    private Tenant defaultWorkspace() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Default Workspace");
        return tenant;
    }
}
