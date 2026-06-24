package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.FindingDeltaQueueEntry;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.ComponentVulnerabilityStateRepository;
import com.prototype.vulnwatch.repo.FindingDeltaQueueEntryRepository;
import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * BLG-006: Durable delta queue backed by PostgreSQL.
 *
 * Replaces the previous in-memory ThreadPoolTaskExecutor approach, which lost events
 * on application restart and dropped them silently under backpressure.
 *
 * Events are written transactionally to finding_delta_queue and processed by a
 * scheduled poller using SELECT FOR UPDATE SKIP LOCKED, giving exactly-once
 * delivery within the JVM lifecycle and automatic retry on failure.
 */
@Service
public class FindingDeltaQueueService {

    private static final Logger LOG = LoggerFactory.getLogger(FindingDeltaQueueService.class);
    static final String SOFTWARE_DELTA = "SOFTWARE_DELTA";
    static final String CVE_DELTA = "CVE_DELTA";
    static final String CVE_METADATA_DELTA = "CVE_METADATA_DELTA";
    static final String VEX_DELTA = "VEX_DELTA";
    static final String LIFECYCLE_DELTA = "LIFECYCLE_DELTA";
    static final String NOISE_REDUCTION_REFRESH = "NOISE_REDUCTION_REFRESH";

    private static final int POLL_BATCH_SIZE = 100;
    private static final int SOFTWARE_BATCH_SIZE = 250;
    private static final int CVE_BATCH_SIZE = 100;
    private static final int CVE_METADATA_BATCH_SIZE = 250;
    private static final int LIFECYCLE_BATCH_SIZE = 500;

    private final FindingDeltaQueueEntryRepository repository;
    private final ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository;
    private final FindingRecomputeService findingRecomputeService;
    private final DashboardNoiseReductionProjectionService dashboardNoiseReductionProjectionService;
    private final TenantService tenantService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;

    public FindingDeltaQueueService(
            FindingDeltaQueueEntryRepository repository,
            ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository,
            FindingRecomputeService findingRecomputeService,
            DashboardNoiseReductionProjectionService dashboardNoiseReductionProjectionService,
            TenantService tenantService,
            TenantSchemaExecutionService tenantSchemaExecutionService
    ) {
        this.repository = repository;
        this.componentVulnerabilityStateRepository = componentVulnerabilityStateRepository;
        this.findingRecomputeService = findingRecomputeService;
        this.dashboardNoiseReductionProjectionService = dashboardNoiseReductionProjectionService;
        this.tenantService = tenantService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
    }

    // -------------------------------------------------------------------------
    // Public enqueueing API — same signatures as before
    // -------------------------------------------------------------------------

    @Transactional
    public int enqueueSoftwareDeltas(UUID tenantId, Collection<UUID> componentIds, String sourceTag) {
        if (tenantId == null || componentIds == null || componentIds.isEmpty()) {
            return 0;
        }
        int queued = 0;
        for (UUID componentId : sortedUniqueIds(componentIds)) {
            String key = "software:" + tenantId + ":" + componentId + ":" + normalizeTag(sourceTag);
            int inserted = repository.insertIfNotDuplicate(
                    SOFTWARE_DELTA, tenantId, componentId, null, null, normalizeTag(sourceTag), key);
            queued += inserted;
        }
        return queued;
    }

    @Transactional
    public int enqueueCveDeltas(Collection<UUID> vulnerabilityIds, String sourceTag) {
        if (vulnerabilityIds == null || vulnerabilityIds.isEmpty()) {
            return 0;
        }
        int queued = 0;
        for (UUID vulnerabilityId : sortedUniqueIds(vulnerabilityIds)) {
            String key = "cve:" + vulnerabilityId + ":" + normalizeTag(sourceTag);
            int inserted = repository.insertIfNotDuplicate(
                    CVE_DELTA, null, null, vulnerabilityId, null, normalizeTag(sourceTag), key);
            queued += inserted;
        }
        return queued;
    }

    @Transactional
    public int enqueueCveMetadataDeltas(Collection<UUID> vulnerabilityIds, String sourceTag) {
        if (vulnerabilityIds == null || vulnerabilityIds.isEmpty()) {
            return 0;
        }
        int queued = 0;
        for (UUID vulnerabilityId : sortedUniqueIds(vulnerabilityIds)) {
            String key = "cve-metadata:" + vulnerabilityId + ":" + normalizeTag(sourceTag);
            int inserted = repository.insertIfNotDuplicate(
                    CVE_METADATA_DELTA, null, null, vulnerabilityId, null, normalizeTag(sourceTag), key);
            queued += inserted;
        }
        return queued;
    }

    @Transactional
    public int enqueueVexDeltas(Collection<UUID> vulnerabilityIds, String sourceKey, String sourceTag) {
        if (vulnerabilityIds == null || vulnerabilityIds.isEmpty()) {
            return 0;
        }
        int queued = 0;
        for (UUID vulnerabilityId : sortedUniqueIds(vulnerabilityIds)) {
            String normalizedSourceKey = normalizeTag(sourceKey);
            String normalizedTag      = normalizeTag(sourceTag);
            String key = "vex:" + vulnerabilityId + ":" + normalizedSourceKey + ":" + normalizedTag;
            int inserted = repository.insertIfNotDuplicate(
                    VEX_DELTA, null, null, vulnerabilityId, normalizedSourceKey, normalizedTag, key);
            queued += inserted;
        }
        return queued;
    }

    @Transactional
    public int enqueueLifecycleDeltas(UUID tenantId, Collection<UUID> componentIds, String sourceTag) {
        if (tenantId == null || componentIds == null || componentIds.isEmpty()) {
            return 0;
        }
        int queued = 0;
        for (UUID componentId : sortedUniqueIds(componentIds)) {
            String key = "lifecycle:" + tenantId + ":" + componentId + ":" + normalizeTag(sourceTag);
            int inserted = repository.insertIfNotDuplicate(
                    LIFECYCLE_DELTA, tenantId, componentId, null, null, normalizeTag(sourceTag), key);
            queued += inserted;
        }
        return queued;
    }

    @Transactional
    public int enqueueNoiseReductionRefresh(UUID tenantId, String sourceTag) {
        if (tenantId == null) {
            return 0;
        }
        return repository.insertIfNotDuplicate(
                NOISE_REDUCTION_REFRESH,
                tenantId,
                null,
                null,
                null,
                normalizeTag(sourceTag),
                "noise:" + tenantId
        );
    }

    public long queueDepth() {
        return repository.countPending();
    }

    // -------------------------------------------------------------------------
    // Scheduled poller — runs every 2 s by default, configurable
    // -------------------------------------------------------------------------

    @Scheduled(fixedDelayString = "${app.correlation.delta-queue-poll-interval-ms:2000}")
    public void processPendingDeltas() {
        // finding_delta_queue is per-tenant. The scheduler thread carries no tenant context, so the
        // queue claim + status updates land in the default schema — without iterating tenants this only
        // ever drained tenant_default and left every other tenant's deltas PENDING forever (so their
        // findings/projections never recomputed). Drain each tenant's queue inside its own schema
        // context. Never let an exception escape: a @Scheduled task that throws is not rescheduled.
        try {
            for (Tenant tenant : tenantService.listActiveTenants()) {
                try {
                    tenantSchemaExecutionService.run(tenant, () -> {
                        List<FindingDeltaQueueEntry> claimed = claimBatch();
                        if (!claimed.isEmpty()) {
                            LOG.debug("Delta queue: claimed {} entries for tenant {}", claimed.size(), tenant.getId());
                            processClaimedBatch(claimed);
                        }
                        return null;
                    });
                } catch (Exception ex) {
                    LOG.warn("Delta queue processing failed for tenant {}: {}", tenant.getId(), ex.getMessage(), ex);
                }
            }
        } catch (Exception ex) {
            LOG.warn("Delta queue poll cycle failed before tenant iteration: {}", ex.getMessage(), ex);
        }
    }

    // -------------------------------------------------------------------------
    // Internal — transactional helpers called via Spring proxy
    // -------------------------------------------------------------------------

    @Transactional
    List<FindingDeltaQueueEntry> claimBatch() {
        List<FindingDeltaQueueEntry> entries = repository.pollPending(POLL_BATCH_SIZE);
        if (entries.isEmpty()) {
            return entries;
        }
        Instant now = Instant.now();
        for (FindingDeltaQueueEntry e : entries) {
            e.setStatus("PROCESSING");
            e.setProcessingStartedAt(now);
            e.setAttemptCount(e.getAttemptCount() + 1);
        }
        repository.saveAll(entries);
        return entries;
    }

    // Not @Transactional — manages its own sub-transactions via findingRecomputeService
    void processClaimedBatch(List<FindingDeltaQueueEntry> claimed) {
        Map<String, List<FindingDeltaQueueEntry>> byType = claimed.stream()
                .collect(Collectors.groupingBy(FindingDeltaQueueEntry::getEventType, java.util.LinkedHashMap::new, Collectors.toList()));
        byType.forEach((eventType, entries) -> {
            switch (eventType) {
                case SOFTWARE_DELTA -> processSoftwareEntries(entries);
                case CVE_DELTA -> processVulnerabilityEntries(entries, CVE_BATCH_SIZE, ids -> findingRecomputeService.recomputeOnCveDeltaBatch(ids));
                case CVE_METADATA_DELTA -> processVulnerabilityEntries(entries, CVE_METADATA_BATCH_SIZE, ids -> findingRecomputeService.refreshMetadataForVulnerabilityBatch(ids));
                case VEX_DELTA -> processVexEntries(entries);
                case LIFECYCLE_DELTA -> processLifecycleEntries(entries);
                case NOISE_REDUCTION_REFRESH -> processNoiseReductionEntries(entries);
                default -> entries.forEach(this::processEntryIndividually);
            }
        });
    }

    private void processSoftwareEntries(List<FindingDeltaQueueEntry> entries) {
        Map<UUID, List<FindingDeltaQueueEntry>> byTenant = entries.stream()
                .filter(entry -> entry.getTenantId() != null && entry.getComponentId() != null)
                .collect(Collectors.groupingBy(FindingDeltaQueueEntry::getTenantId, java.util.LinkedHashMap::new, Collectors.toList()));
        byTenant.values().forEach(tenantEntries -> processComponentEntries(tenantEntries, SOFTWARE_BATCH_SIZE, false));
        entries.stream()
                .filter(entry -> entry.getTenantId() == null || entry.getComponentId() == null)
                .forEach(entry -> markDone(entry.getId(), 0));
    }

    private void processLifecycleEntries(List<FindingDeltaQueueEntry> entries) {
        Map<UUID, List<FindingDeltaQueueEntry>> byTenant = entries.stream()
                .filter(entry -> entry.getTenantId() != null && entry.getComponentId() != null)
                .collect(Collectors.groupingBy(FindingDeltaQueueEntry::getTenantId, java.util.LinkedHashMap::new, Collectors.toList()));
        byTenant.values().forEach(tenantEntries -> processComponentEntries(tenantEntries, LIFECYCLE_BATCH_SIZE, true));
        entries.stream()
                .filter(entry -> entry.getTenantId() == null || entry.getComponentId() == null)
                .forEach(entry -> markDone(entry.getId(), 0));
    }

    private void processComponentEntries(
            List<FindingDeltaQueueEntry> entries,
            int batchSize,
            boolean lifecycleOnly
    ) {
        UUID tenantId = entries.get(0).getTenantId();
        for (List<FindingDeltaQueueEntry> chunk : chunk(entries, batchSize)) {
            try {
                List<UUID> componentIds = chunk.stream()
                        .map(FindingDeltaQueueEntry::getComponentId)
                        .filter(Objects::nonNull)
                        .distinct()
                        .toList();
                int affected = runInTenantSchema(
                        tenantId,
                        () -> lifecycleOnly
                                ? findingRecomputeService.refreshLifecycleForComponents(tenantId, componentIds)
                                : findingRecomputeService.recomputeOnSoftwareDeltaBatch(tenantId, componentIds)
                );
                markDone(chunk.stream().map(FindingDeltaQueueEntry::getId).toList(), affected);
                if (!lifecycleOnly) {
                    enqueueNoiseReductionRefresh(tenantId, "software-delta");
                }
            } catch (RuntimeException ex) {
                LOG.warn("Failed processing {} component delta entries for tenant {}: {}",
                        lifecycleOnly ? "lifecycle" : "software", tenantId, ex.getMessage(), ex);
                markFailedOrRetry(chunk, ex.getMessage());
            }
        }
    }

    private void processVulnerabilityEntries(
            List<FindingDeltaQueueEntry> entries,
            int batchSize,
            java.util.function.Function<Collection<UUID>, Integer> processor
    ) {
        List<FindingDeltaQueueEntry> validEntries = entries.stream()
                .filter(entry -> entry.getVulnerabilityId() != null)
                .toList();
        for (List<FindingDeltaQueueEntry> chunk : chunk(validEntries, batchSize)) {
            try {
                List<UUID> vulnerabilityIds = chunk.stream()
                        .map(FindingDeltaQueueEntry::getVulnerabilityId)
                        .filter(Objects::nonNull)
                        .distinct()
                        .toList();
                int affected = processor.apply(vulnerabilityIds);
                markDone(chunk.stream().map(FindingDeltaQueueEntry::getId).toList(), affected);
                enqueueNoiseReductionRefreshForTenants(
                        componentVulnerabilityStateRepository.findDistinctTenantIdsByVulnerabilityIds(vulnerabilityIds),
                        "vulnerability-delta"
                );
            } catch (RuntimeException ex) {
                LOG.warn("Failed processing vulnerability delta entries type={}: {}",
                        validEntries.isEmpty() ? "unknown" : validEntries.get(0).getEventType(), ex.getMessage(), ex);
                markFailedOrRetry(chunk, ex.getMessage());
            }
        }
        entries.stream()
                .filter(entry -> entry.getVulnerabilityId() == null)
                .forEach(entry -> markDone(entry.getId(), 0));
    }

    private void processVexEntries(List<FindingDeltaQueueEntry> entries) {
        Map<String, List<FindingDeltaQueueEntry>> bySourceKey = entries.stream()
                .collect(Collectors.groupingBy(entry -> normalizeTag(entry.getSourceKey()), java.util.LinkedHashMap::new, Collectors.toList()));
        bySourceKey.forEach((sourceKey, sourceEntries) -> {
            List<FindingDeltaQueueEntry> validEntries = sourceEntries.stream()
                    .filter(entry -> entry.getVulnerabilityId() != null)
                    .toList();
            for (List<FindingDeltaQueueEntry> chunk : chunk(validEntries, CVE_BATCH_SIZE)) {
                try {
                    List<UUID> vulnerabilityIds = chunk.stream()
                            .map(FindingDeltaQueueEntry::getVulnerabilityId)
                            .filter(Objects::nonNull)
                            .distinct()
                            .toList();
                    int affected = findingRecomputeService.applyVexDeltaBatch(vulnerabilityIds, sourceKey);
                    markDone(chunk.stream().map(FindingDeltaQueueEntry::getId).toList(), affected);
                    enqueueNoiseReductionRefreshForTenants(
                            componentVulnerabilityStateRepository.findDistinctTenantIdsByVulnerabilityIds(vulnerabilityIds),
                            "vex-delta"
                    );
                } catch (RuntimeException ex) {
                    LOG.warn("Failed processing VEX delta entries sourceKey={}: {}", sourceKey, ex.getMessage(), ex);
                    markFailedOrRetry(chunk, ex.getMessage());
                }
            }
            sourceEntries.stream()
                    .filter(entry -> entry.getVulnerabilityId() == null)
                    .forEach(entry -> markDone(entry.getId(), 0));
        });
    }

    private void processNoiseReductionEntries(List<FindingDeltaQueueEntry> entries) {
        Map<UUID, List<FindingDeltaQueueEntry>> byTenant = entries.stream()
                .filter(entry -> entry.getTenantId() != null)
                .collect(Collectors.groupingBy(FindingDeltaQueueEntry::getTenantId, java.util.LinkedHashMap::new, Collectors.toList()));
        byTenant.forEach((tenantId, tenantEntries) -> {
            try {
                int refreshed = runInTenantSchema(tenantId, () -> dashboardNoiseReductionProjectionService.refreshTenant(tenantId));
                markDone(tenantEntries.stream().map(FindingDeltaQueueEntry::getId).toList(), refreshed);
            } catch (RuntimeException ex) {
                LOG.warn("Failed processing noise reduction refresh for tenant {}: {}", tenantId, ex.getMessage(), ex);
                markFailedOrRetry(tenantEntries, ex.getMessage());
            }
        });
        entries.stream()
                .filter(entry -> entry.getTenantId() == null)
                .forEach(entry -> markDone(entry.getId(), 0));
    }

    void processEntryIndividually(FindingDeltaQueueEntry entry) {
        try {
            int affected = switch (entry.getEventType()) {
                case SOFTWARE_DELTA -> runInTenantSchema(
                        entry.getTenantId(),
                        () -> findingRecomputeService.recomputeOnSoftwareDelta(entry.getTenantId(), entry.getComponentId()));
                case CVE_DELTA -> findingRecomputeService.recomputeOnCveDelta(
                        entry.getVulnerabilityId());
                case CVE_METADATA_DELTA -> findingRecomputeService.refreshMetadataForVulnerabilityBatch(
                        entry.getVulnerabilityId() == null ? List.of() : List.of(entry.getVulnerabilityId()));
                case VEX_DELTA -> findingRecomputeService.applyVexDeltaForVulnerability(
                        entry.getVulnerabilityId(), entry.getSourceKey());
                case LIFECYCLE_DELTA -> runInTenantSchema(
                        entry.getTenantId(),
                        () -> findingRecomputeService.refreshLifecycleForComponents(
                                entry.getTenantId(),
                                entry.getComponentId() == null ? List.of() : List.of(entry.getComponentId())));
                case NOISE_REDUCTION_REFRESH -> runInTenantSchema(
                        entry.getTenantId(),
                        () -> dashboardNoiseReductionProjectionService.refreshTenant(entry.getTenantId()));
                default -> {
                    LOG.warn("Unknown delta event type '{}' for entry id={}", entry.getEventType(), entry.getId());
                    yield 0;
                }
            };
            markDone(entry.getId(), affected);
        } catch (RuntimeException ex) {
            LOG.warn("Failed processing delta entry id={} type={}: {}",
                    entry.getId(), entry.getEventType(), ex.getMessage(), ex);
            markFailedOrRetry(entry.getId(), entry.getAttemptCount(), entry.getMaxAttempts(), ex.getMessage());
        }
    }

    @Transactional
    void markDone(Long id, int affected) {
        markDone(List.of(id), affected);
    }

    @Transactional
    void markDone(Collection<Long> ids, int affected) {
        Instant completedAt = Instant.now();
        for (Long id : ids) {
            repository.findById(id).ifPresent(e -> {
                e.setStatus("DONE");
                e.setCompletedAt(completedAt);
                repository.save(e);
                LOG.debug("Delta entry id={} type={} marked DONE, affected={}", id, e.getEventType(), affected);
            });
        }
    }

    @Transactional
    void markFailedOrRetry(Long id, int attemptCount, int maxAttempts, String errorMessage) {
        repository.findById(id).ifPresent(e -> {
            e.setErrorMessage(errorMessage);
            if (attemptCount >= maxAttempts) {
                e.setStatus("FAILED");
                LOG.error("Delta entry id={} type={} FAILED after {} attempts: {}",
                        id, e.getEventType(), attemptCount, errorMessage);
            } else {
                // Exponential backoff: 1 min, 2 min, 4 min, ...
                long backoffSeconds = 60L * (1L << (attemptCount - 1));
                e.setStatus("PENDING");
                e.setVisibleAfter(Instant.now().plusSeconds(backoffSeconds));
                LOG.warn("Delta entry id={} type={} scheduled for retry in {}s (attempt {}/{})",
                        id, e.getEventType(), backoffSeconds, attemptCount, maxAttempts);
            }
            repository.save(e);
        });
    }

    void markFailedOrRetry(List<FindingDeltaQueueEntry> entries, String errorMessage) {
        entries.forEach(entry ->
                markFailedOrRetry(entry.getId(), entry.getAttemptCount(), entry.getMaxAttempts(), errorMessage));
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private List<UUID> sortedUniqueIds(Collection<UUID> ids) {
        return ids.stream()
                .filter(id -> id != null)
                .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new))
                .stream()
                .sorted(UUID::compareTo)
                .toList();
    }

    private <T> List<List<T>> chunk(List<T> entries, int chunkSize) {
        if (entries == null || entries.isEmpty()) {
            return List.of();
        }
        List<List<T>> chunks = new java.util.ArrayList<>();
        for (int start = 0; start < entries.size(); start += chunkSize) {
            int end = Math.min(start + chunkSize, entries.size());
            chunks.add(entries.subList(start, end));
        }
        return chunks;
    }

    private static String normalizeTag(String value) {
        if (value == null || value.isBlank()) {
            return "default";
        }
        return value.trim().toLowerCase(Locale.ROOT);
    }

    private void enqueueNoiseReductionRefreshForTenants(Collection<UUID> tenantIds, String sourceTag) {
        if (tenantIds == null || tenantIds.isEmpty()) {
            return;
        }
        for (UUID tenantId : tenantIds) {
            enqueueNoiseReductionRefresh(tenantId, sourceTag);
        }
    }

    private int runInTenantSchema(UUID tenantId, java.util.function.IntSupplier supplier) {
        if (tenantId == null) {
            return supplier.getAsInt();
        }
        var tenant = tenantService.resolveTenantUuid(tenantId);
        UUID previousTenantId = TenantContext.getCurrentTenantId();
        String previousSchema = TenantContext.getCurrentSchemaName();
        try {
            TenantContext.setCurrentTenantId(tenantId);
            TenantContext.setCurrentSchemaName(tenant.getSchemaName());
            return supplier.getAsInt();
        } finally {
            if (previousTenantId == null) {
                TenantContext.clear();
            } else {
                TenantContext.setCurrentTenantId(previousTenantId);
                TenantContext.setCurrentSchemaName(previousSchema);
            }
        }
    }
}
