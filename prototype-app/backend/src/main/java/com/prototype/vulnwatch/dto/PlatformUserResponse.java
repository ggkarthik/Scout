package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record PlatformUserResponse(
        UUID userId,
        String externalSubject,
        String email,
        String displayName,
        String status,
        List<String> globalRoles,
        boolean passwordSet,
        boolean setupPending,
        Instant passwordSetAt,
        Instant lastSetupIssuedAt,
        Instant lastSetupCompletedAt,
        Instant lastSeenAt,
        Instant createdAt
) {
}
