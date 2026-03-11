package com.prototype.vulnwatch.dto;

public record VexRolloutComparisonResponse(
        VexRolloutMetricsSnapshotResponse before,
        VexRolloutMetricsSnapshotResponse after
) {
}
