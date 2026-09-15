package com.prototype.vulnwatch.dto;

import java.time.Instant;

public record TenantInviteValidationResponse(
        boolean valid,
        String status,
        String email,
        String tenantId,
        String tenantName,
        String inviteeName,
        String role,
        Instant inviteExpiresAt,
        String message,
        String setupToken
) {
}
