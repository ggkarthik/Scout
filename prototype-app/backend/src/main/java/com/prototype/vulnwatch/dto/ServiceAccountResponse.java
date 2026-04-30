package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record ServiceAccountResponse(
        UUID id,
        UUID tenantId,
        String name,
        String keyId,
        String role,
        String status,
        Instant createdAt,
        Instant lastUsedAt
) {
}
