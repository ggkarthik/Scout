package com.prototype.vulnwatch.dto;

import java.time.Instant;

public record VexRolloutMetricsSnapshotResponse(
        long vexLikeTargetCount,
        long persistedAssertionCount,
        long activeMatchedComponentCount,
        long activeApplicableAwaitingVexCount,
        Instant capturedAt
) {
}
