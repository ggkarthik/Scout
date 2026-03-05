package com.prototype.vulnwatch.dto;

import java.util.List;

public record OperationalIngestionEfficiencyResponse(
        long sbomIngestionsLast24h,
        double sbomIngestionsPerHour,
        double sbomSuccessRatePercent,
        long syncRunsLast24h,
        double syncSuccessRatePercent,
        long queueBacklog,
        long recordsFetchedLast24h,
        long recordsInsertedLast24h,
        long recordsUpdatedLast24h,
        List<OperationalIngestionSourceMetricResponse> sourceBreakdown
) {
}
