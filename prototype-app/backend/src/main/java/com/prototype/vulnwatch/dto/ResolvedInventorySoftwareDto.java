package com.prototype.vulnwatch.dto;

import java.util.List;

public record ResolvedInventorySoftwareDto(
        String id,
        String software,
        String vendor,
        String version,
        List<InventoryAssetItemDto> assets,
        String lifecycle,
        String endOfSupport,
        String endOfLife,
        String recommendedUpgrade
) {}
