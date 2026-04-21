package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record EolUnresolvedMappingDto(
        UUID softwareIdentityId,
        String vendor,
        String product,
        String displayName,
        String normalizedKey,
        long assetCount,
        long componentCount,
        long versionCount,
        long openFindingCount,
        long openVulnerabilityCount,
        Instant lastObservedAt
) {
}
