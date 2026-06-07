package com.prototype.vulnwatch.dto;

public record AssetCriterionDto(
        String id,
        String software,
        String version,
        String vendor
) {}
