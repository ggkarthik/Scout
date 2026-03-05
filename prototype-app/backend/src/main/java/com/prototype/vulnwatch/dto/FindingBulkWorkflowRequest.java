package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record FindingBulkWorkflowRequest(
        List<UUID> findingIds,
        Boolean applyToFiltered,
        List<String> severity,
        List<String> status,
        List<String> decisionState,
        List<String> matchMethod,
        List<String> vexStatus,
        List<String> vexFreshness,
        List<String> vexProvider,
        Double minConfidence,
        String vulnerabilityId,
        String packageName,
        String ecosystem,
        String workflowStatus,
        String assignedTo,
        Instant dueAt,
        String suppressionReason,
        Instant suppressedUntil,
        String actor
) {
}
