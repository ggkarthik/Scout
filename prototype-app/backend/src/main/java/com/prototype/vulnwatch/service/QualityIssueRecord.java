package com.prototype.vulnwatch.service;

import java.time.Instant;
import java.util.UUID;

public record QualityIssueRecord(
        String id,
        UUID tenantId,
        String issueKey,
        String domain,
        String issueType,
        String severity,
        String reasonCode,
        String sourceObjectType,
        String sourceObjectId,
        UUID assetId,
        UUID componentId,
        UUID softwareIdentityId,
        UUID vulnerabilityId,
        UUID syncRunId,
        String title,
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
        Instant lastComputedAt,
        String evidenceJson,
        String drilldownJson
) {
}
