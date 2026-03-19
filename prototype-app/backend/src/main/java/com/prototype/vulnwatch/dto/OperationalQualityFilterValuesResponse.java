package com.prototype.vulnwatch.dto;

import java.util.List;

public record OperationalQualityFilterValuesResponse(
        List<String> domains,
        List<String> issueTypes,
        List<String> severities,
        List<String> assetTypes,
        List<String> sourceSystems,
        List<String> ecosystems
) {
}
