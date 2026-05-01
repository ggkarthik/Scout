package com.prototype.vulnwatch.dto;

import java.time.Instant;

public record TestPersonaTokenResponse(
        String token,
        String tokenType,
        Instant expiresAt,
        TestPersonaResponse persona
) {
}
