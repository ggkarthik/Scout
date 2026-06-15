package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record IngestionJobResponse(
        UUID jobId,
        String jobType,
        String sourceType,
        String assetIdentifier,
        String status,
        String requestedBy,
        Instant requestedAt,
        Instant startedAt,
        Instant completedAt,
        int attemptCount,
        String failureCode,
        String failureMessage,
        UUID sbomUploadId,
        String resultJson
) {
}
