package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record DemoInviteResponse(
        UUID id,
        UUID requestId,
        UUID tenantId,
        String tenantName,
        String email,
        String status,
        Instant expiresAt,
        Instant acceptedAt,
        Instant lastSentAt,
        String inviteUrl
) {
}
