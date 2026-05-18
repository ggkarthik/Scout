package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record TenantSupportGrantResponse(
        UUID id,
        UUID tenantId,
        String tenantName,
        String invitedPlatformSubject,
        String reason,
        String scope,
        String accessMode,
        String status,
        String grantedBySubject,
        String acceptedBySubject,
        String revokedBySubject,
        Instant requestedAt,
        Instant acceptedAt,
        Instant expiresAt,
        Instant revokedAt
) {
}
