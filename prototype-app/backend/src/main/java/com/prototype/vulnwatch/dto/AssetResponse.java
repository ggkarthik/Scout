package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record AssetResponse(
        UUID id,
        String type,
        String name,
        String identifier,
        String serviceName,
        String environment,
        String ownerTeam,
        String ownerEmail,
        String businessCriticality,
        String state,
        Instant lastInventoryAt,
        Instant lastCmdbSyncAt
) {
}
