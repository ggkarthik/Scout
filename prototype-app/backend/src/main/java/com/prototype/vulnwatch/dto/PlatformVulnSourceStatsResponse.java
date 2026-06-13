package com.prototype.vulnwatch.dto;

import java.util.Map;

public record PlatformVulnSourceStatsResponse(
        Map<String, SourceStat> sources
) {
    public record SourceStat(
            long total,
            long critical,
            long high,
            long medium,
            long low,
            long unknown
    ) {}
}
