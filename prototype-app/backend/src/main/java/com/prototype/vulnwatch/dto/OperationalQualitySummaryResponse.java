package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;

public record OperationalQualitySummaryResponse(
        Instant generatedAt,
        long totalIssues,
        long criticalIssues,
        long affectsActiveFindingsCount,
        long newIssuesLast24h,
        List<OperationalQualityDomainCountResponse> domainCounts
) {
}
