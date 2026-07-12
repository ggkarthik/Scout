package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record HostFindingResponse(
        UUID id,
        String displayId,
        String vulnerabilityId,
        String packageName,
        String packageVersion,
        String severity,
        String status,
        String decisionState,
        Double riskScore,
        Double confidenceScore,
        String matchedBy,
        String assignedTo,
        String ownerGroup,
        String creationSource,
        Instant dueAt,
        Instant firstObservedAt,
        Instant lastObservedAt
) {
}
