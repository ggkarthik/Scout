package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

/**
 * A logical BOM source and what it currently claims.
 *
 * <p>Needed before a caller can replace a source: replacement is now explicit, so the client
 * has to be able to name the source it means. Also carries the evidence counts and the
 * standing completeness assertion, since a source asserting complete asset software is the
 * only thing that can authorise retiring a component.
 */
public record BomSourceResponse(
        UUID id,
        UUID assetId,
        String bomType,
        String supplier,
        String sourceKey,
        String sourceReference,
        UUID currentBomId,
        long revision,
        String completeness,
        String state,
        Instant createdAt,
        Instant updatedAt,
        long supportedComponentCount,
        long withdrawnComponentCount,
        String latestAssertionBy,
        Instant latestAssertionAt
) {
}
