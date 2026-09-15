package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record DemoInviteValidationResponse(
        boolean valid,
        String status,
        String email,
        UUID tenantId,
        String tenantName,
        Instant demoExpiresAt,
        Instant inviteExpiresAt,
        String loginUrl,
        String message,
        String setupToken
) {
}
