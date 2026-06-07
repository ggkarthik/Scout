package com.prototype.vulnwatch.dto;

import java.util.List;

public record FindingPortfolioRollupResponse(
        long totalOpenCount,
        long totalCriticalOpenCount,
        long totalOverdueOpenCount,
        List<FindingPortfolioQueueRollupResponse> queueRollups,
        List<FindingQueueWorkloadBreakdownResponse> topOwnerGroups,
        List<FindingQueueWorkloadBreakdownResponse> topSupportGroups
) {}
