package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record OrgSpecificCveExposureRecordResponse(
        UUID stateId,
        UUID vulnerabilityId,
        String externalId,
        String component,
        String version,
        String applicability,
        boolean impacted,
        String impactState,
        String severity,
        Double cvssScore,
        Instant lastEvaluatedAt
) {
}
