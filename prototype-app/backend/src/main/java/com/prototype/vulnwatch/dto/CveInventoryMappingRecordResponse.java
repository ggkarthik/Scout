package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record CveInventoryMappingRecordResponse(
        UUID vulnerabilityId,
        String externalId,
        String severity,
        Double cvssScore,
        Double epssScore,
        boolean inKev,
        long impactedComponentCount,
        long noPatchComponentCount,
        Instant lastModifiedAt,
        List<String> mappedCpes,
        List<String> mappedSoftware,
        long mappedSoftwareCount
) {
}
