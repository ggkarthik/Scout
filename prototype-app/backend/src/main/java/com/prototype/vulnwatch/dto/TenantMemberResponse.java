package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record TenantMemberResponse(
        UUID id,
        UUID userId,
        String subject,
        String email,
        String displayName,
        String role,
        String status,
        Instant createdAt
) {
}
