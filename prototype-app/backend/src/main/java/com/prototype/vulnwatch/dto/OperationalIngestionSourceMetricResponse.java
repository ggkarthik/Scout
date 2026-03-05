package com.prototype.vulnwatch.dto;

public record OperationalIngestionSourceMetricResponse(
        String source,
        long runs,
        long successes,
        long failures,
        double successRatePercent,
        long fetched,
        long inserted,
        long updated
) {
}
