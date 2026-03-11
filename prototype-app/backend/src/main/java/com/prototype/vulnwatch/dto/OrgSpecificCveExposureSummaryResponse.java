package com.prototype.vulnwatch.dto;

public record OrgSpecificCveExposureSummaryResponse(
        long reviewQueueCount,
        long applicableCount,
        long impactedCount,
        long underInvestigationCount,
        long resolvedCount
) {
}
