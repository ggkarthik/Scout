package com.prototype.vulnwatch.dto;

import java.util.List;

public record FindingQueueAnalyticsResponse(
        List<FindingQueueAgingBucketResponse> agingBuckets,
        double reopenRatePercent,
        long reopenedCountLast30Days,
        long assignedOpenCount,
        long unassignedOpenCount,
        long withIncidentCount,
        long withoutIncidentCount,
        long oldestOpenAgeDays,
        long medianOpenAgeDays,
        List<FindingQueueWorkloadBreakdownResponse> topOwners,
        List<FindingQueueWorkloadBreakdownResponse> topSupportGroups
) {
}
