package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record HostFindingResponse(
        UUID id,
        String vulnerabilityId,
        String severity,
        String status,
        String decisionState,
        Double riskScore,
        Double confidenceScore,
        String matchedBy,
        Instant firstObservedAt,
        Instant lastObservedAt
) {
}
