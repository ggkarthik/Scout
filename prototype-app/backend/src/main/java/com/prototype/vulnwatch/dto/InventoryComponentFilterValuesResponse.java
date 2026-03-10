package com.prototype.vulnwatch.dto;

import java.util.List;

public record InventoryComponentFilterValuesResponse(
        List<String> assetTypes,
        List<String> componentStatuses,
        List<String> sourceSystems,
        List<String> ecosystems
) {
}
