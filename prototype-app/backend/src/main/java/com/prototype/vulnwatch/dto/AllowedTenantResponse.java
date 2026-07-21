package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record AllowedTenantResponse(
        String id,
        String name,
        String slug,
        String role,
        String accessMode,
        UUID accessReferenceId,
        Instant expiresAt,
        boolean revocable
) {
}
