package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record TenantInviteResponse(
        UUID id,
        UUID tenantId,
        String email,
        String displayName,
        String subject,
        String role,
        String status,
        Instant createdAt,
        Instant expiresAt,
        Instant acceptedAt,
        Instant lastSentAt,
        String invitedBySubject,
        String invitedByDisplayName,
        String deliveryDetail
) {
}
