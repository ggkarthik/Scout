package com.prototype.vulnwatch.service.vulningestion;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.IngestionResult;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.VulnerabilitySourceFilterConfigService;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.task.TaskExecutor;
import org.springframework.stereotype.Service;

@Service
public class CsafSyncService {

    private static final Logger LOG = LoggerFactory.getLogger(CsafSyncService.class);

    private final VulnerabilitySourceFilterConfigService vulnerabilitySourceFilterConfigService;
    private final TenantService tenantService;
    private final TaskExecutor ingestionExecutor;
    private final VulnerabilitySyncRunService syncRunService;
    private final VulnerabilityIngestionEffectsService effectsService;
    private final CsafDiscoveryService discoveryService;
    private final CsafDocumentFetcher documentFetcher;
    private final CsafDocumentIngestor documentIngestor;
    private final ObjectMapper objectMapper;

    @Value("${app.csaf.max-documents-per-sync:300}")
    private int csafMaxDocumentsPerSync;

    public CsafSyncService(
            VulnerabilitySourceFilterConfigService vulnerabilitySourceFilterConfigService,
            TenantService tenantService,
            @Qualifier("integrationQueueExecutor") TaskExecutor ingestionExecutor,
            VulnerabilitySyncRunService syncRunService,
            VulnerabilityIngestionEffectsService effectsService,
            CsafDiscoveryService discoveryService,
            CsafDocumentFetcher documentFetcher,
            CsafDocumentIngestor documentIngestor,
            ObjectMapper objectMapper
    ) {
        this.vulnerabilitySourceFilterConfigService = vulnerabilitySourceFilterConfigService;
        this.tenantService = tenantService;
        this.ingestionExecutor = ingestionExecutor;
        this.syncRunService = syncRunService;
        this.effectsService = effectsService;
        this.discoveryService = discoveryService;
        this.documentFetcher = documentFetcher;
        this.documentIngestor = documentIngestor;
        this.objectMapper = objectMapper;
    }

    public void runScheduledMicrosoftSync() {
        syncMicrosoftCsaf();
    }

    public void runScheduledRedhatSync() {
        syncRedhatCsaf();
    }

    public SyncTriggerResponse triggerMicrosoftCsafSync() {
        java.util.Optional<SyncRun> activeRun = syncRunService.findFirstActiveRun(List.of("CSAF_MICROSOFT", "VEX_ROLLOUT_BACKFILL"));
        if (activeRun.isPresent()) {
            SyncRun run = activeRun.get();
            return new SyncTriggerResponse(run.getId(), run.getStatus(), "Microsoft CSAF/VEX sync is already in progress");
        }
        SyncRun run = syncRunService.createQueuedRun("CSAF_MICROSOFT");
        ingestionExecutor.execute(() -> executeMicrosoftCsafSyncAsync(run.getId()));
        return new SyncTriggerResponse(run.getId(), run.getStatus(), "Microsoft CSAF/VEX sync queued");
    }

    public void executeMicrosoftCsafSyncAsync(UUID runId) {
        SyncRun run = syncRunService.markRunning(runId);
        executeCsafSync(run, CsafProvider.MICROSOFT);
    }

    public IngestionResult syncMicrosoftCsaf() {
        SyncRun run = syncRunService.createRunningRun("CSAF_MICROSOFT");
        return executeCsafSync(run, CsafProvider.MICROSOFT);
    }

    public SyncTriggerResponse triggerRedhatCsafSync() {
        java.util.Optional<SyncRun> activeRun = syncRunService.findFirstActiveRun(List.of("CSAF_REDHAT", "VEX_ROLLOUT_BACKFILL"));
        if (activeRun.isPresent()) {
            SyncRun run = activeRun.get();
            return new SyncTriggerResponse(run.getId(), run.getStatus(), "Red Hat CSAF/VEX sync is already in progress");
        }
        SyncRun run = syncRunService.createQueuedRun("CSAF_REDHAT");
        ingestionExecutor.execute(() -> executeRedhatCsafSyncAsync(run.getId()));
        return new SyncTriggerResponse(run.getId(), run.getStatus(), "Red Hat CSAF/VEX sync queued");
    }

    public void executeRedhatCsafSyncAsync(UUID runId) {
        SyncRun run = syncRunService.markRunning(runId);
        executeCsafSync(run, CsafProvider.REDHAT);
    }

    public IngestionResult syncRedhatCsaf() {
        SyncRun run = syncRunService.createRunningRun("CSAF_REDHAT");
        return executeCsafSync(run, CsafProvider.REDHAT);
    }

    private IngestionResult executeCsafSync(SyncRun run, CsafProvider provider) {
        int fetched = 0;
        int inserted = 0;
        int updated = 0;
        int failed = 0;
        Set<UUID> changedVulnerabilityIds = new LinkedHashSet<>();
        Set<UUID> vexChangedVulnerabilityIds = new LinkedHashSet<>();
        CsafRunDiagnostics diagnostics = new CsafRunDiagnostics(provider.providerKey());
        VulnerabilitySourceFilterConfigService.RedhatFilters redhatFilters = provider == CsafProvider.REDHAT
                ? vulnerabilitySourceFilterConfigService.resolveRedhatFilters(defaultTenant())
                : new VulnerabilitySourceFilterConfigService.RedhatFilters(null, null, null);
        if (provider == CsafProvider.REDHAT) {
            syncRunService.applyRunMetadata(run, "redhat", syncRunService.redhatFiltersMetadata(redhatFilters));
        }
        try {
            CsafDistributionSet distributions = discoveryService.discoverDistributions(provider);
            List<CsafDocumentRef> documents = discoveryService.collectDocumentRefs(distributions, provider);
            int maxDocs = Math.max(1, csafMaxDocumentsPerSync);
            if (documents.size() > maxDocs) {
                documents = new ArrayList<>(documents.subList(0, maxDocs));
            }

            for (CsafDocumentRef document : documents) {
                diagnostics.markDocumentAttempt();
                CsafDocumentFetchResult fetchResult = documentFetcher.fetch(document.url());
                if (!fetchResult.success()) {
                    failed++;
                    diagnostics.markDocumentFailure(fetchResult.failureCategory(), fetchResult.attempts());
                    LOG.warn(
                            "Failed to fetch {} advisory {} category={} attempts={} message={}",
                            provider.providerKey(),
                            document.url(),
                            fetchResult.failureCategory(),
                            fetchResult.attempts(),
                            fetchResult.failureMessage());
                    run.setRecordsFetched(fetched);
                    run.setRecordsInserted(inserted);
                    run.setRecordsUpdated(updated);
                    run.setRecordsFailed(failed);
                    syncRunService.save(run);
                    continue;
                }
                try {
                    JsonNode advisoryNode = objectMapper.readTree(fetchResult.body());
                    CsafIngestionCounters counters = documentIngestor.ingestDocument(
                            provider,
                            advisoryNode,
                            document.url(),
                            document.vexProfile(),
                            diagnostics,
                            redhatFilters
                    );
                    inserted += counters.inserted();
                    updated += counters.updated();
                    if (document.vexProfile()) {
                        vexChangedVulnerabilityIds.addAll(counters.vulnerabilityIds());
                    } else {
                        changedVulnerabilityIds.addAll(counters.vulnerabilityIds());
                    }
                    fetched++;
                    diagnostics.markDocumentSuccess(fetchResult.attempts());
                    run.setRecordsFetched(fetched);
                    run.setRecordsInserted(inserted);
                    run.setRecordsUpdated(updated);
                    run.setRecordsFailed(failed);
                    syncRunService.save(run);
                } catch (Exception advisoryError) {
                    failed++;
                    String category = documentFetcher.failureCategory(advisoryError);
                    diagnostics.markDocumentFailure(category, fetchResult.attempts());
                    LOG.warn(
                            "Failed to ingest {} advisory {} category={} attempts={}",
                            provider.providerKey(),
                            document.url(),
                            category,
                            fetchResult.attempts(),
                            advisoryError);
                    run.setRecordsFetched(fetched);
                    run.setRecordsInserted(inserted);
                    run.setRecordsUpdated(updated);
                    run.setRecordsFailed(failed);
                    syncRunService.save(run);
                }
            }

            Set<UUID> allChangedVulnerabilityIds = new LinkedHashSet<>(changedVulnerabilityIds);
            allChangedVulnerabilityIds.addAll(vexChangedVulnerabilityIds);
            effectsService.refreshAssertionsForVulnerabilityIds(allChangedVulnerabilityIds);
            effectsService.recomputeCveDeltas(allChangedVulnerabilityIds);
            effectsService.applyVexDeltas(vexChangedVulnerabilityIds, provider.providerKey());
            LOG.info("CSAF run diagnostics {}", diagnostics.summaryLine());
            String message = provider.displayName() + " CSAF/VEX sync complete"
                    + (failed > 0 ? " (failed advisories: " + failed + ")" : "");
            syncRunService.completeRun(
                    run,
                    "completed",
                    fetched,
                    inserted,
                    updated,
                    failed,
                    failed > 0 ? diagnostics.summaryLine() : null
            );
            return new IngestionResult("ok", fetched, inserted, updated, message);
        } catch (Exception e) {
            syncRunService.completeRun(run, "failed", fetched, inserted, updated, failed, e.getMessage());
            return new IngestionResult("failed", fetched, inserted, updated, e.getMessage());
        }
    }

    private Tenant defaultTenant() {
        return tenantService.getDefaultTenant();
    }
}
