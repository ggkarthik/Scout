package com.prototype.vulnwatch.dto;

import java.time.Instant;

public record AuthSessionResponse(
        String token,
        String tokenType,
        Instant expiresAt
) {
}
