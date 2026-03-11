package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record InventoryComponentResponse(
        UUID id,
        UUID assetId,
        String assetName,
        String assetIdentifier,
        String assetType,
        String componentStatus,
        String ecosystem,
        String packageName,
        String version,
        String normalizedName,
        String normalizedVersion,
        String purl,
        String componentDigest,
        String softwareIdentity,
        String sourceSystem,
        String sourceType,
        String sourceReference,
        Instant uploadedAt,
        Instant lastObservedAt,
        Instant retiredAt
) {
}
