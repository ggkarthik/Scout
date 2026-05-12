package com.prototype.vulnwatch.dto;

import jakarta.validation.constraints.NotNull;
import java.util.UUID;

public record AuthTenantContextRequest(
        @NotNull UUID tenantId
) {
}
