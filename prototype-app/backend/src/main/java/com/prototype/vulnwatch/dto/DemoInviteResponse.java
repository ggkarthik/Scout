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
        String deliveryStatus,
        String deliveryMessage,
        Instant expiresAt,
        Instant acceptedAt,
        Instant lastSentAt,
        Instant deliveryAttemptedAt,
        String inviteUrl
) {
}
