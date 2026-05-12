package com.prototype.vulnwatch.dto;

import java.time.Instant;

public record AuthTokenResponse(
        String token,
        String tokenType,
        Instant expiresAt
) {
}
