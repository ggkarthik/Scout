package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;

public record VulnRepoSoftwareAssetsResponse(
        String softwareIdentityId,
        String displayName,
        String vendor,
        long impactedAssetCount,
        List<AssetItem> assets
) {
    public record AssetItem(
            String assetId,
            String assetName,
            String assetIdentifier,
            String assetType,
            String componentId,
            String version,
            String sourceSystem,
            long openCveCount,
            long openFindingCount,
            Instant lastObservedAt
    ) {
    }
}
