package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.time.LocalDate;
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
        Instant retiredAt,
        boolean needsReview,
        int reviewItemCount,
        boolean reviewMissingVersion,
        boolean reviewUnmappedSoftware,
        boolean reviewLowConfidenceAlias,
        boolean reviewDiscoveryModel,
        String eolSlug,
        String eolCycle,
        LocalDate eolDate,
        Boolean isEol,
        Integer eolDaysRemaining
) {
}
