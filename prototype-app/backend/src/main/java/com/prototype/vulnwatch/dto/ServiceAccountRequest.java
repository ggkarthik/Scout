package com.prototype.vulnwatch.dto;

import java.util.UUID;

public record ServiceAccountRequest(
        UUID tenantId,
        String name,
        String keyId,
        String role
) {
}
