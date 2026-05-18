package com.prototype.vulnwatch.dto;

import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.Instant;

public record TenantSupportGrantRequest(
        @NotBlank String invitedPlatformSubject,
        @NotBlank String reason,
        String scope,
        String accessMode,
        @NotNull @Future Instant expiresAt
) {
}
