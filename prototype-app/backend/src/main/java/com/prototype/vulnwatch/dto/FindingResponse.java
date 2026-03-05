package com.prototype.vulnwatch.dto;

import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingStatus;
import java.time.Instant;
import java.util.UUID;

public record FindingResponse(
        UUID id,
        String assetName,
        String assetType,
        String packageName,
        String packageVersion,
        String vulnerabilityId,
        String source,
        String severity,
        boolean inKev,
        Double epss,
        double riskScore,
        double confidenceScore,
        String matchedBy,
        String assignedTo,
        Instant dueAt,
        String suppressionReason,
        Instant suppressedUntil,
        String evidence,
        String precedenceTrace,
        Instant firstObservedAt,
        Instant lastObservedAt,
        FindingDecisionState decisionState,
        FindingStatus status,
        Instant updatedAt
) {
}
