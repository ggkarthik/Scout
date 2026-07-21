package com.prototype.vulnwatch.dto;

import jakarta.validation.constraints.NotBlank;
import java.time.Instant;

public record TenantSupportGrantRequest(
        @NotBlank String invitedPlatformSubject,
        @NotBlank String reason,
        String scope,
        String accessMode,
        Instant expiresAt
) {
}
