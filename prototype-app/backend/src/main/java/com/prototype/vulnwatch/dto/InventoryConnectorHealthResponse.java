package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record InventoryConnectorHealthResponse(
        UUID tenantId,
        String tenantName,
        String connectorKey,
        boolean enabled,
        boolean autoSyncEnabled,
        String lastTestStatus,
        String lastTestMessage,
        Instant lastTestedAt,
        Instant lastSyncAt,
        String healthState
) {
}
