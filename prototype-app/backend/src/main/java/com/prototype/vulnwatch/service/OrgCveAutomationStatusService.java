package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.OrgCveAutomationStatusResponse;
import com.prototype.vulnwatch.repo.FindingDeltaQueueEntryRepository;
import com.prototype.vulnwatch.repo.OrgCveRecordRepository;
import com.prototype.vulnwatch.repo.SyncRunRepository;
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
    private final OrgCveRecordRepository orgCveRecordRepository;
    private final SyncRunRepository syncRunRepository;

    @Value("${app.slo.queue-stale-threshold-minutes:10}")
    private long queueStaleThresholdMinutes;

    public OrgCveAutomationStatusService(
            FindingDeltaQueueEntryRepository findingDeltaQueueEntryRepository,
            OrgCveRecordRepository orgCveRecordRepository,
            SyncRunRepository syncRunRepository
    ) {
        this.findingDeltaQueueEntryRepository = findingDeltaQueueEntryRepository;
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

        Instant staleThreshold = Instant.now().minus(queueStaleThresholdMinutes, ChronoUnit.MINUTES);
        Instant lastLifecycleSweepAt = syncRunRepository
                .findTopBySyncTypeIgnoreCaseOrderByStartedAtDesc("EOL_DATE_SWEEP")
                .map(run -> run.getCompletedAt() != null ? run.getCompletedAt() : run.getStartedAt())
                .orElse(null);

        return new OrgCveAutomationStatusResponse(
                true,
                findingDeltaQueueEntryRepository.countPending(),
                Map.copyOf(pendingByType),
                findingDeltaQueueEntryRepository.countStaleVisible(staleThreshold),
                findingDeltaQueueEntryRepository.countFailed(),
                findingDeltaQueueEntryRepository.findLatestCompletedAt(),
                tenant == null ? null : orgCveRecordRepository.findLatestLastEvaluatedAt(tenant),
                lastLifecycleSweepAt
        );
    }
}
