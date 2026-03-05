package com.prototype.vulnwatch.dto;

import java.time.Instant;

public record OperationalSourceFreshnessResponse(
        String source,
        Instant lastSuccessfulAt,
        long ageHours,
        boolean stale
) {
}
