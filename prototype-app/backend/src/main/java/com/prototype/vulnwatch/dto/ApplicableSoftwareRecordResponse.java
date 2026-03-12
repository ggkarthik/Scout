package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record ApplicableSoftwareRecordResponse(
        UUID componentId,
        UUID assetId,
        String assetName,
        String assetIdentifier,
        String ecosystem,
        String packageName,
        String version,
        long applicableCveCount,
        long awaitingVexCveCount,
        long vexMatchedCveCount,
        long impactedCveCount,
        long noPatchCveCount,
        Instant lastEvaluatedAt
) {
}
