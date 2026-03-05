package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record SyncRunResponse(
        UUID id,
        String syncType,
        String status,
        Integer queuePosition,
        int recordsFetched,
        int recordsInserted,
        int recordsUpdated,
        int recordsFailed,
        Instant startedAt,
        Instant completedAt,
        String errorMessage
) {
}
