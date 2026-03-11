package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.FindingDeltaQueueEntry;
import com.prototype.vulnwatch.repo.FindingDeltaQueueEntryRepository;
import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
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
    private static final int POLL_BATCH_SIZE = 20;

    private final FindingDeltaQueueEntryRepository repository;
    private final FindingService findingService;

    public FindingDeltaQueueService(
            FindingDeltaQueueEntryRepository repository,
            FindingService findingService
    ) {
        this.repository = repository;
        this.findingService = findingService;
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
                    "SOFTWARE_DELTA", tenantId, componentId, null, null, normalizeTag(sourceTag), key);
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
                    "CVE_DELTA", null, null, vulnerabilityId, null, normalizeTag(sourceTag), key);
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
                    "VEX_DELTA", null, null, vulnerabilityId, normalizedSourceKey, normalizedTag, key);
            queued += inserted;
        }
        return queued;
    }

    public long queueDepth() {
        return repository.countPending();
    }

    // -------------------------------------------------------------------------
    // Scheduled poller — runs every 2 s by default, configurable
    // -------------------------------------------------------------------------

    @Scheduled(fixedDelayString = "${app.correlation.delta-queue-poll-interval-ms:2000}")
    public void processPendingDeltas() {
        List<FindingDeltaQueueEntry> claimed = claimBatch();
        if (claimed.isEmpty()) {
            return;
        }
        LOG.debug("Delta queue: claimed {} entries for processing", claimed.size());
        for (FindingDeltaQueueEntry entry : claimed) {
            processEntry(entry);
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

    // Not @Transactional — manages its own sub-transactions via findingService
    void processEntry(FindingDeltaQueueEntry entry) {
        try {
            int affected = switch (entry.getEventType()) {
                case "SOFTWARE_DELTA" -> findingService.recomputeOnSoftwareDelta(
                        entry.getTenantId(), entry.getComponentId());
                case "CVE_DELTA"      -> findingService.recomputeOnCveDelta(
                        entry.getVulnerabilityId());
                case "VEX_DELTA"      -> findingService.applyVexDeltaForVulnerability(
                        entry.getVulnerabilityId(), entry.getSourceKey());
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
        repository.findById(id).ifPresent(e -> {
            e.setStatus("DONE");
            e.setCompletedAt(Instant.now());
            repository.save(e);
            LOG.debug("Delta entry id={} type={} marked DONE, affected={}", id, e.getEventType(), affected);
        });
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

    private static String normalizeTag(String value) {
        if (value == null || value.isBlank()) {
            return "default";
        }
        return value.trim().toLowerCase(Locale.ROOT);
    }
}
