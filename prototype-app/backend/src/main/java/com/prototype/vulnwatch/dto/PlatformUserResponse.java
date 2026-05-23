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
        Instant lastSeenAt,
        Instant createdAt
) {
}
