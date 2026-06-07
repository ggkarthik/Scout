package com.prototype.vulnwatch.dto;

public record EolAnalysisResultDto(
        String id,
        String software,
        String vendor,
        String version,
        String lifecycle,
        String endOfSupport,
        String endOfLife,
        String recommendedUpgrade
) {}
