package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record ImpactedCveRecordResponse(
        UUID vulnerabilityId,
        String externalId,
        String severity,
        Double cvssScore,
        Double epssScore,
        boolean inKev,
        long impactedComponentCount,
        long impactedAssetCount,
        long noPatchComponentCount,
        Instant lastEvaluatedAt,
        Instant lastModifiedAt
) {
}
