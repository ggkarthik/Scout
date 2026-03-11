package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record SyncRunSnapshotResponse(
        UUID runId,
        String status,
        Instant startedAt,
        Instant completedAt,
        String errorMessage
) {
}
