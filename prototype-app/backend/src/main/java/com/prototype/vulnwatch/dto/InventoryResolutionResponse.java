package com.prototype.vulnwatch.dto;

import java.util.List;

public record InventoryResolutionResponse(
        List<ResolvedInventorySoftwareDto> resolved,
        int totalAssets
) {}
