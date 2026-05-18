package com.prototype.vulnwatch.dto;

import java.time.Instant;

public record AllowedTenantResponse(
        String id,
        String name,
        String slug,
        String role,
        String accessMode,
        Instant expiresAt
) {
}
