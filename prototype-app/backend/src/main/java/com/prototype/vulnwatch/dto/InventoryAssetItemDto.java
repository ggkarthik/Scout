package com.prototype.vulnwatch.dto;

public record InventoryAssetItemDto(
        String componentId,
        String assetId,
        String assetName,
        String assetIdentifier,
        String assetType,
        String packageName,
        String version,
        String ecosystem,
        Boolean isEol,
        String eolDate,
        String eolSupportEndDate
) {}
