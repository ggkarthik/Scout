package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record FindingEventResponse(
        UUID id,
        String eventType,
        String actor,
        String summary,
        String detailsJson,
        Instant createdAt
) {
}
