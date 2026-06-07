package com.prototype.vulnwatch.dto;

public record FindingPortfolioQueueRollupResponse(
        String queueKey,
        String title,
        long matchingCount,
        long openCount,
        long criticalOpenCount,
        long overdueOpenCount,
        long unassignedOpenCount,
        long withIncidentCount
) {}
