package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.OrgCveAutomationStatusResponse;
import com.prototype.vulnwatch.repo.FindingDeltaQueueEntryRepository;
import com.prototype.vulnwatch.repo.IngestionJobRepository;
import com.prototype.vulnwatch.repo.OrgCveRecordRepository;
import com.prototype.vulnwatch.repo.SyncRunRepository;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class OrgCveAutomationStatusService {

    private final FindingDeltaQueueEntryRepository findingDeltaQueueEntryRepository;
    private final IngestionJobRepository ingestionJobRepository;
    private final OrgCveRecordRepository orgCveRecordRepository;
    private final SyncRunRepository syncRunRepository;

    @Value("${app.slo.queue-stale-threshold-minutes:10}")
    private long queueStaleThresholdMinutes;

    public OrgCveAutomationStatusService(
            FindingDeltaQueueEntryRepository findingDeltaQueueEntryRepository,
            IngestionJobRepository ingestionJobRepository,
            OrgCveRecordRepository orgCveRecordRepository,
            SyncRunRepository syncRunRepository
    ) {
        this.findingDeltaQueueEntryRepository = findingDeltaQueueEntryRepository;
        this.ingestionJobRepository = ingestionJobRepository;
        this.orgCveRecordRepository = orgCveRecordRepository;
        this.syncRunRepository = syncRunRepository;
    }

    @Transactional(readOnly = true)
    public OrgCveAutomationStatusResponse getStatus(Tenant tenant) {
        Map<String, Long> pendingByType = new LinkedHashMap<>();
        pendingByType.put(FindingDeltaQueueService.SOFTWARE_DELTA, 0L);
        pendingByType.put(FindingDeltaQueueService.CVE_DELTA, 0L);
        pendingByType.put(FindingDeltaQueueService.CVE_METADATA_DELTA, 0L);
        pendingByType.put(FindingDeltaQueueService.VEX_DELTA, 0L);
        pendingByType.put(FindingDeltaQueueService.LIFECYCLE_DELTA, 0L);
        findingDeltaQueueEntryRepository.countPendingByEventType()
                .forEach(row -> pendingByType.put(row.getEventType(), row.getEntryCount()));

        Instant now = Instant.now();
        Instant staleThreshold = now.minus(queueStaleThresholdMinutes, ChronoUnit.MINUTES);
        FindingDeltaQueueEntryRepository.StatusSummaryRow queueSummary =
                findingDeltaQueueEntryRepository.summarizeStatus(now);
        IngestionJobRepository.StatusSummaryRow ingestionSummary =
                ingestionJobRepository.summarizeStatus(now);
        long pendingEventCount = queueSummary == null ? 0L : queueSummary.getPendingCount();
        long processingEventCount = queueSummary == null ? 0L : queueSummary.getProcessingCount();
        long staleEventCount = findingDeltaQueueEntryRepository.countStaleVisible(staleThreshold);
        long failedEventCount = queueSummary == null ? 0L : queueSummary.getFailedCount();
        long oldestPendingEventAgeSeconds = ageSeconds(
                queueSummary == null ? null : queueSummary.getOldestVisiblePendingAt(),
                now
        );
        long oldestProcessingEventAgeSeconds = ageSeconds(
                queueSummary == null ? null : queueSummary.getOldestProcessingStartedAt(),
                now
        );
        long ingestionQueuedJobCount = ingestionSummary == null ? 0L : ingestionSummary.getQueuedCount();
        long ingestionRunningJobCount = ingestionSummary == null ? 0L : ingestionSummary.getRunningCount();
        long oldestQueuedIngestionAgeSeconds = ageSeconds(
                ingestionSummary == null ? null : ingestionSummary.getOldestVisibleQueuedAt(),
                now
        );
        long oldestRunningIngestionAgeSeconds = ageSeconds(
                ingestionSummary == null ? null : ingestionSummary.getOldestRunningStartedAt(),
                now
        );
        Instant lastLifecycleSweepAt = syncRunRepository
                .findTopBySyncTypeIgnoreCaseOrderByStartedAtDesc("EOL_DATE_SWEEP")
                .map(run -> run.getCompletedAt() != null ? run.getCompletedAt() : run.getStartedAt())
                .orElse(null);

        return new OrgCveAutomationStatusResponse(
                true,
                pendingEventCount,
                processingEventCount,
                Map.copyOf(pendingByType),
                staleEventCount,
                failedEventCount,
                oldestPendingEventAgeSeconds,
                oldestProcessingEventAgeSeconds,
                ingestionQueuedJobCount,
                ingestionRunningJobCount,
                oldestQueuedIngestionAgeSeconds,
                oldestRunningIngestionAgeSeconds,
                queueSummary == null ? null : queueSummary.getLatestCompletedAt(),
                tenant == null ? null : orgCveRecordRepository.findLatestLastEvaluatedAt(tenant),
                lastLifecycleSweepAt
        );
    }

    private long ageSeconds(Instant startedAt, Instant now) {
        if (startedAt == null || now == null || startedAt.isAfter(now)) {
            return 0L;
        }
        return Math.max(0L, Duration.between(startedAt, now).getSeconds());
    }
}
