package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.Map;

public record OrgCveAutomationStatusResponse(
        boolean automationEnabled,
        long pendingEventCount,
        long processingEventCount,
        Map<String, Long> pendingByType,
        long staleEventCount,
        long failedEventCount,
        long oldestPendingEventAgeSeconds,
        long oldestProcessingEventAgeSeconds,
        long ingestionQueuedJobCount,
        long ingestionRunningJobCount,
        long oldestQueuedIngestionAgeSeconds,
        long oldestRunningIngestionAgeSeconds,
        Instant lastProcessedAt,
        Instant latestOrgCveEvaluatedAt,
        Instant lastLifecycleSweepAt
) {
}
