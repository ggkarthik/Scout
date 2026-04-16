package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record HostAssetSummaryResponse(
        UUID assetId,
        UUID ciId,
        String name,
        String identifier,
        String sysId,
        String environment,
        String ownerEmail,
        String managedBy,
        String department,
        String supportGroup,
        String assignedTo,
        String businessCriticality,
        String state,
        Instant lastInventoryAt,
        Instant lastCmdbSyncAt,
        int aliasCount,
        int installedSoftwareCount,
        int openFindingCount,
        int totalFindingCount,
        int unresolvedReviewCount
) {
}
