package com.prototype.vulnwatch.service;

import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.task.TaskRejectedException;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.stereotype.Service;

@Service
public class FindingDeltaQueueService {

    private static final Logger LOG = LoggerFactory.getLogger(FindingDeltaQueueService.class);

    private final FindingService findingService;
    private final ThreadPoolTaskExecutor findingDeltaExecutor;
    private final Set<String> dedupeKeys = java.util.concurrent.ConcurrentHashMap.newKeySet();
    private final long enqueueTimeoutMs;

    public FindingDeltaQueueService(
            FindingService findingService,
            @Qualifier("findingDeltaExecutor") ThreadPoolTaskExecutor findingDeltaExecutor,
            @Value("${app.correlation.delta-queue-enqueue-timeout-ms:2000}") long enqueueTimeoutMs
    ) {
        this.findingService = findingService;
        this.findingDeltaExecutor = findingDeltaExecutor;
        this.enqueueTimeoutMs = Math.max(50, enqueueTimeoutMs);
    }

    public int enqueueSoftwareDeltas(UUID tenantId, Collection<UUID> componentIds, String sourceTag) {
        if (tenantId == null || componentIds == null || componentIds.isEmpty()) {
            return 0;
        }
        int queued = 0;
        for (UUID componentId : sortedUniqueIds(componentIds)) {
            if (enqueue(DeltaEvent.softwareDelta(tenantId, componentId, sourceTag))) {
                queued++;
            }
        }
        return queued;
    }

    public int enqueueCveDeltas(Collection<UUID> vulnerabilityIds, String sourceTag) {
        if (vulnerabilityIds == null || vulnerabilityIds.isEmpty()) {
            return 0;
        }
        int queued = 0;
        for (UUID vulnerabilityId : sortedUniqueIds(vulnerabilityIds)) {
            if (enqueue(DeltaEvent.cveDelta(vulnerabilityId, sourceTag))) {
                queued++;
            }
        }
        return queued;
    }

    public int enqueueVexDeltas(Collection<UUID> vulnerabilityIds, String sourceKey, String sourceTag) {
        if (vulnerabilityIds == null || vulnerabilityIds.isEmpty()) {
            return 0;
        }
        int queued = 0;
        for (UUID vulnerabilityId : sortedUniqueIds(vulnerabilityIds)) {
            if (enqueue(DeltaEvent.vexDelta(vulnerabilityId, sourceKey, sourceTag))) {
                queued++;
            }
        }
        return queued;
    }

    public int queueDepth() {
        if (findingDeltaExecutor.getThreadPoolExecutor() == null) {
            return 0;
        }
        return findingDeltaExecutor.getThreadPoolExecutor().getQueue().size();
    }

    private boolean enqueue(DeltaEvent event) {
        if (event == null || event.key() == null) {
            return false;
        }
        if (!dedupeKeys.add(event.key())) {
            return false;
        }

        long deadlineNanos = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(enqueueTimeoutMs);
        while (true) {
            try {
                findingDeltaExecutor.execute(() -> processEvent(event));
                return true;
            } catch (TaskRejectedException rejected) {
                if (System.nanoTime() >= deadlineNanos) {
                    dedupeKeys.remove(event.key());
                    LOG.error(
                            "Finding delta queue backpressure: DROPPED event key={} type={} vulnerabilityId={} tenantId={} depth={} timeoutMs={} — recompute may be required",
                            event.key(),
                            event.type(),
                            event.vulnerabilityId(),
                            event.tenantId(),
                            queueDepth(),
                            enqueueTimeoutMs
                    );
                    return false;
                }
                try {
                    Thread.sleep(25L);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    dedupeKeys.remove(event.key());
                    return false;
                }
            }
        }
    }

    private void processEvent(DeltaEvent event) {
        try {
            int affected = switch (event.type()) {
                case SOFTWARE_DELTA -> findingService.recomputeOnSoftwareDelta(
                        event.tenantId(),
                        event.componentId());
                case CVE_DELTA -> findingService.recomputeOnCveDelta(event.vulnerabilityId());
                case VEX_DELTA -> findingService.applyVexDeltaForVulnerability(
                        event.vulnerabilityId(),
                        event.sourceKey());
            };
            LOG.debug(
                    "Processed finding delta type={} key={} affected={} queuedAt={} queueDepth={}",
                    event.type(),
                    event.key(),
                    affected,
                    event.enqueuedAt(),
                    queueDepth()
            );
        } catch (RuntimeException exception) {
            LOG.warn(
                    "Failed processing finding delta key={} type={}: {}",
                    event.key(),
                    event.type(),
                    exception.getMessage(),
                    exception
            );
        } finally {
            dedupeKeys.remove(event.key());
        }
    }

    private List<UUID> sortedUniqueIds(Collection<UUID> ids) {
        return ids.stream()
                .filter(id -> id != null)
                .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new))
                .stream()
                .sorted(UUID::compareTo)
                .toList();
    }

    private enum DeltaType {
        SOFTWARE_DELTA,
        CVE_DELTA,
        VEX_DELTA
    }

    private record DeltaEvent(
            DeltaType type,
            UUID tenantId,
            UUID componentId,
            UUID vulnerabilityId,
            String sourceKey,
            String sourceTag,
            Instant enqueuedAt,
            String key
    ) {

        static DeltaEvent softwareDelta(UUID tenantId, UUID componentId, String sourceTag) {
            String normalizedTag = normalizeTag(sourceTag);
            String key = "software:" + tenantId + ":" + componentId + ":" + normalizedTag;
            return new DeltaEvent(
                    DeltaType.SOFTWARE_DELTA,
                    tenantId,
                    componentId,
                    null,
                    null,
                    normalizedTag,
                    Instant.now(),
                    key
            );
        }

        static DeltaEvent cveDelta(UUID vulnerabilityId, String sourceTag) {
            String normalizedTag = normalizeTag(sourceTag);
            String key = "cve:" + vulnerabilityId + ":" + normalizedTag;
            return new DeltaEvent(
                    DeltaType.CVE_DELTA,
                    null,
                    null,
                    vulnerabilityId,
                    null,
                    normalizedTag,
                    Instant.now(),
                    key
            );
        }

        static DeltaEvent vexDelta(UUID vulnerabilityId, String sourceKey, String sourceTag) {
            String normalizedSourceKey = normalizeTag(sourceKey);
            String normalizedTag = normalizeTag(sourceTag);
            String key = "vex:" + vulnerabilityId + ":" + normalizedSourceKey + ":" + normalizedTag;
            return new DeltaEvent(
                    DeltaType.VEX_DELTA,
                    null,
                    null,
                    vulnerabilityId,
                    normalizedSourceKey,
                    normalizedTag,
                    Instant.now(),
                    key
            );
        }

        private static String normalizeTag(String value) {
            if (value == null || value.isBlank()) {
                return "default";
            }
            return value.trim().toLowerCase(Locale.ROOT);
        }
    }
}
