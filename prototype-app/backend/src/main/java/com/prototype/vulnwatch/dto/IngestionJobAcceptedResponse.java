package com.prototype.vulnwatch.dto;

import java.util.UUID;

public record IngestionJobAcceptedResponse(
        UUID jobId,
        String status,
        String message,
        boolean existingJob,
        Integer retryAfterSeconds
) {
}
