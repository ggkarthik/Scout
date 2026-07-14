package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record TenantSchemaStatusResponse(
        List<Item> items,
        int page,
        int size,
        long total
) {
    public record Item(
            UUID tenantId,
            String schemaName,
            int currentVersion,
            int targetVersion,
            String status,
            String structuralChecksum,
            int lastSuccessfulVersion,
            String failureCode,
            String failureMessage,
            Instant migrationStartedAt,
            Instant migrationCompletedAt,
            Instant updatedAt,
            UUID migrationRunId
    ) {
    }
}
