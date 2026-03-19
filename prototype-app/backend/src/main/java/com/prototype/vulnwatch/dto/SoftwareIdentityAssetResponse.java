package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.time.LocalDate;
import java.util.UUID;

public record SoftwareIdentityAssetResponse(
        UUID assetId,
        String assetName,
        String assetIdentifier,
        String assetType,
        UUID componentId,
        String packageName,
        String ecosystem,
        String version,
        String sourceSystem,
        String eolSlug,
        String eolCycle,
        LocalDate eolDate,
        Boolean isEol,
        Integer eolDaysRemaining,
        long openFindingCount,
        long openVulnerabilityCount,
        Instant lastObservedAt
) {
}
