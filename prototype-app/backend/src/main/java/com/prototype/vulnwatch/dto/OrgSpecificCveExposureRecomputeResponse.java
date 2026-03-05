package com.prototype.vulnwatch.dto;

import java.time.Instant;

public record OrgSpecificCveExposureRecomputeResponse(
        String scope,
        long activeComponentCount,
        int correlatedExposureCount,
        int stateRowsChanged,
        long exposureStateRowCount,
        long openFindingsCount,
        Instant recomputedAt
) {
}
