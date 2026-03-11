package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.Set;

public record VexAssertionRepairSummaryResponse(
        long vexLikeTargetCount,
        long persistedAssertionCount,
        long activeMatchedComponentCount,
        long activeApplicableAwaitingVexCount,
        Set<String> sourceSystems,
        boolean vexPolicyEnabled,
        boolean vexRiskModifiersEnabled,
        boolean vexRolloutControlsEnabled,
        boolean vexRolloutBackfillEnabled,
        SyncRunSnapshotResponse latestRepairRun,
        SyncRunSnapshotResponse latestMicrosoftRun,
        SyncRunSnapshotResponse latestRedhatRun,
        SyncRunSnapshotResponse latestBackfillRun,
        VexRolloutComparisonResponse latestBackfillComparison,
        Instant generatedAt
) {
}
