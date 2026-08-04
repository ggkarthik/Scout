package com.prototype.vulnwatch.dto;

import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.NotNull;
import java.time.Instant;

public record TenantDemoExpiryRequest(
        @NotNull @Future Instant expiresAt
) {
}
