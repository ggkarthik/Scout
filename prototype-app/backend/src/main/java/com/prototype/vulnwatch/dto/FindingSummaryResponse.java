package com.prototype.vulnwatch.dto;

public record FindingSummaryResponse(
        long openCount,
        long criticalOpenCount,
        long withIncidentCount,
        long unassignedOpenCount,
        long overdueOpenCount,
        long noSlaOpenCount
) {
}
