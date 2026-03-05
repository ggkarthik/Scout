package com.prototype.vulnwatch.dto;

import java.time.Instant;

public record FindingWorkflowUpdateRequest(
        String status,
        String assignedTo,
        Instant dueAt,
        String suppressionReason,
        Instant suppressedUntil,
        String actor
) {
}
