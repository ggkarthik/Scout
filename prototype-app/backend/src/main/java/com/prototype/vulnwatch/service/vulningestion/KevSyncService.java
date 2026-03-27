package com.prototype.vulnwatch.service.vulningestion;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundFailureDecision;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicy;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.IngestionResult;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.service.ObservationIngestionService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.VulnerabilityIntelligenceService;
import com.prototype.vulnwatch.service.VulnerabilitySourceFilterConfigService;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.task.TaskExecutor;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;

@Service
public class KevSyncService {

    private static final String KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

    private final ObservationIngestionService observationIngestionService;
    private final VulnerabilitySourceFilterConfigService vulnerabilitySourceFilterConfigService;
    private final TenantService tenantService;
    private final TaskExecutor ingestionExecutor;
    private final VulnerabilitySyncRunService syncRunService;
    private final VulnerabilityIngestionEffectsService effectsService;
    private final VulnerabilityIngestionCommonSupport support;
    private final OutboundHttpClient outboundHttpClient;
    private final OutboundPolicyFactory outboundPolicyFactory;
    private final ObjectMapper objectMapper;

    public KevSyncService(
            ObservationIngestionService observationIngestionService,
            VulnerabilitySourceFilterConfigService vulnerabilitySourceFilterConfigService,
            TenantService tenantService,
            @Qualifier("integrationQueueExecutor") TaskExecutor ingestionExecutor,
            VulnerabilitySyncRunService syncRunService,
            VulnerabilityIngestionEffectsService effectsService,
            VulnerabilityIngestionCommonSupport support,
            OutboundHttpClient outboundHttpClient,
            OutboundPolicyFactory outboundPolicyFactory,
            ObjectMapper objectMapper
    ) {
        this.observationIngestionService = observationIngestionService;
        this.vulnerabilitySourceFilterConfigService = vulnerabilitySourceFilterConfigService;
        this.tenantService = tenantService;
        this.ingestionExecutor = ingestionExecutor;
        this.syncRunService = syncRunService;
        this.effectsService = effectsService;
        this.support = support;
        this.outboundHttpClient = outboundHttpClient;
        this.outboundPolicyFactory = outboundPolicyFactory;
        this.objectMapper = objectMapper;
    }

    public void runScheduledDailySync() {
        syncKev();
    }

    public SyncTriggerResponse triggerKevSync() {
        SyncRun run = syncRunService.createQueuedRun("KEV");
        ingestionExecutor.execute(() -> executeKevSyncAsync(run.getId()));
        return new SyncTriggerResponse(run.getId(), run.getStatus(), "KEV sync queued");
    }

    public void executeKevSyncAsync(UUID runId) {
        SyncRun run = syncRunService.markRunning(runId);
        executeKevSync(run);
    }

    public IngestionResult syncKev() {
        SyncRun run = syncRunService.createRunningRun("KEV");
        return executeKevSync(run);
    }

    private IngestionResult executeKevSync(SyncRun run) {
        int fetched = 0;
        int inserted = 0;
        int updated = 0;
        Set<UUID> changedVulnerabilityIds = new LinkedHashSet<>();
        VulnerabilitySourceFilterConfigService.KevFilters filters =
                vulnerabilitySourceFilterConfigService.resolveKevFilters(defaultTenant());
        syncRunService.applyRunMetadata(run, "kev", syncRunService.kevFiltersMetadata(filters));
        try {
            String body = fetchKevFeed();
            JsonNode root = objectMapper.readTree(body == null ? "{}" : body);
            JsonNode vulns = root.path("vulnerabilities");

            for (JsonNode kev : vulns) {
                if (!matchesKevFilters(kev, filters)) {
                    continue;
                }
                String cveId = kev.path("cveID").asText("");
                if (cveId.isBlank()) {
                    continue;
                }
                fetched++;

                VulnerabilityIntelligenceService.ObservationUpsertResult result = observationIngestionService.upsertObservation(
                        new VulnerabilityIntelligenceService.ObservationUpsertRequest(
                                cveId,
                                "kev",
                                cveId,
                                KEV_URL,
                                cveId + " (KEV)",
                                kev.path("vulnerabilityName").asText("KEV flagged vulnerability"),
                                "HIGH",
                                null,
                                null,
                                null,
                                Boolean.TRUE,
                                "KNOWN_EXPLOITED",
                                null,
                                null,
                                null,
                                null,
                                null,
                                kev.toString()
                        )
                );
                if (result.vulnerabilityCreated()) {
                    inserted++;
                } else {
                    updated++;
                }
                if (result.vulnerability() != null && result.vulnerability().getId() != null) {
                    changedVulnerabilityIds.add(result.vulnerability().getId());
                }
            }

            effectsService.enqueueCveMetadataDeltas(changedVulnerabilityIds);

            syncRunService.completeRun(run, "completed", fetched, inserted, updated, 0, null);
            return new IngestionResult("ok", fetched, inserted, updated, "KEV sync complete");
        } catch (Exception e) {
            syncRunService.completeRun(run, "failed", fetched, inserted, updated, 0, e.getMessage());
            return new IngestionResult("failed", fetched, inserted, updated, e.getMessage());
        }
    }

    private boolean matchesKevFilters(
            JsonNode kevNode,
            VulnerabilitySourceFilterConfigService.KevFilters filters
    ) {
        if (filters == null || !filters.configured()) {
            return true;
        }
        if (support.hasText(filters.vendorProject())
                && !support.containsIgnoreCase(kevNode.path("vendorProject").asText(""), filters.vendorProject())) {
            return false;
        }
        if (support.hasText(filters.product())
                && !support.containsIgnoreCase(kevNode.path("product").asText(""), filters.product())) {
            return false;
        }
        java.time.LocalDate dateAdded = support.parseLocalDateOrNull(kevNode.path("dateAdded").asText(""));
        if (filters.dateAddedFrom() != null && (dateAdded == null || dateAdded.isBefore(filters.dateAddedFrom()))) {
            return false;
        }
        if (filters.dateAddedTo() != null && (dateAdded == null || dateAdded.isAfter(filters.dateAddedTo()))) {
            return false;
        }
        java.time.LocalDate dueDate = support.parseLocalDateOrNull(kevNode.path("dueDate").asText(""));
        if (filters.dueDateFrom() != null && (dueDate == null || dueDate.isBefore(filters.dueDateFrom()))) {
            return false;
        }
        if (filters.dueDateTo() != null && (dueDate == null || dueDate.isAfter(filters.dueDateTo()))) {
            return false;
        }
        if (filters.knownRansomwareCampaignUse()
                && !support.isKnownRansomwareCampaignUse(kevNode.path("knownRansomwareCampaignUse").asText(""))) {
            return false;
        }
        return true;
    }

    private Tenant defaultTenant() {
        return tenantService.getDefaultTenant();
    }

    private String fetchKevFeed() {
        try {
            return outboundHttpClient.execute(
                    KEV_URL,
                    HttpMethod.GET,
                    HttpEntity.EMPTY,
                    String.class,
                    "KEV feed request",
                    outboundPolicy(),
                    context -> new OutboundFailureDecision<>(
                            context.isRetryableByDefault(),
                            context.retryAfterDelayMs(),
                            context.error() instanceof RuntimeException runtimeException
                                    ? runtimeException
                                    : new RuntimeException(context.error())
                    ),
                    response -> response.getBody() == null ? "" : response.getBody()
            );
        } catch (RuntimeException runtimeException) {
            throw runtimeException;
        } catch (Exception checkedException) {
            throw new RuntimeException(checkedException);
        }
    }

    private OutboundPolicy outboundPolicy() {
        return outboundPolicyFactory.forProvider("kev", 0L, null, null);
    }
}
