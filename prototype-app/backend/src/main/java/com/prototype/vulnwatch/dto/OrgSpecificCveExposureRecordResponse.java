package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record OrgSpecificCveExposureRecordResponse(
        UUID recordId,
        UUID vulnerabilityId,
        String externalId,
        String title,
        String applicability,
        boolean impacted,
        String impactState,
        String impactReason,
        String severity,
        Double cvssScore,
        Double epssScore,
        boolean inKev,
        long matchedComponentCount,
        long matchedSoftwareCount,
        long openFindings,
        Instant lastEvaluatedAt
) {
}
