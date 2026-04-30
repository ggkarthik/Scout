package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record AuditEventResponse(
        UUID id,
        Instant occurredAt,
        UUID tenantId,
        String actorSubject,
        String actorRole,
        String action,
        String targetType,
        String targetId,
        String outcome,
        String detailsJson
) {
}
