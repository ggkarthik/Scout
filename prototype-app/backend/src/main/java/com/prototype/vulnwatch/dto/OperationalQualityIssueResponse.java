package com.prototype.vulnwatch.dto;

import java.time.Instant;

public record OperationalQualityIssueResponse(
        String id,
        String issueKey,
        String domain,
        String issueType,
        String severity,
        String reasonCode,
        String title,
        String sourceObjectType,
        String sourceObjectId,
        String primaryLabel,
        String secondaryLabel,
        String assetType,
        String sourceSystem,
        String ecosystem,
        boolean affectsActiveFindings,
        long affectedAssetCount,
        long affectedComponentCount,
        long openFindingCount,
        long openVulnerabilityCount,
        Instant firstSeenAt,
        Instant lastSeenAt
) {
}
