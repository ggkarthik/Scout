package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;

public record OperationalQualityIssueDetailResponse(
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
        Instant lastSeenAt,
        String whyThisMatters,
        String evidenceJson,
        String recommendedAction,
        List<OperationalQualityDrilldownTargetResponse> drilldownTargets,
        List<OperationalQualitySampleRecordResponse> sampleRecords,
        boolean hasActiveOverride,
        String overrideActor,
        Instant overrideAt
) {
}
