package com.prototype.vulnwatch.dto;

public record FindingAssetCountResponse(
        String assetName,
        long count
) {
}
