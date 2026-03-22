package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.Map;

public record OrgCveAutomationStatusResponse(
        boolean automationEnabled,
        long pendingEventCount,
        Map<String, Long> pendingByType,
        long staleEventCount,
        long failedEventCount,
        Instant lastProcessedAt,
        Instant latestOrgCveEvaluatedAt,
        Instant lastLifecycleSweepAt
) {
}
