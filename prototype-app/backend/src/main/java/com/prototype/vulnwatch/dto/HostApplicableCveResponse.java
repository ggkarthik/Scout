package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record HostApplicableCveResponse(
        UUID stateId,
        UUID vulnerabilityId,
        String externalId,
        String severity,
        Double cvssScore,
        Double epssScore,
        String packageName,
        String version,
        String impactState,
        Instant lastEvaluatedAt
) {
}
