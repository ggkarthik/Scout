package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.Map;

public record VulnIntelSourceSummary(
        Map<String, SourceStatus> sources
) {
    public record SourceStatus(
            String status,       // "completed" | "failed" | "running" | "never"
            Instant completedAt,
            int recordsInserted,
            int recordsUpdated,
            int recordsFetched,
            String errorMessage
    ) {}
}
