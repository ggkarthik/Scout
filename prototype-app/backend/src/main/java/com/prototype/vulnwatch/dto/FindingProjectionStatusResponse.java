package com.prototype.vulnwatch.dto;

import java.time.Instant;

public record FindingProjectionStatusResponse(
        Instant lastComputedAt,
        long findingCount,
        long sourceFindingCount,
        boolean stale,
        long driftCount,
        Long lastRebuildDurationMs
) {
}
