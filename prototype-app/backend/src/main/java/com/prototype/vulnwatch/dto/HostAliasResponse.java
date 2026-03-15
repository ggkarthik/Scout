package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record HostAliasResponse(
        UUID id,
        String aliasName,
        String sourceSystem,
        Double confidence,
        Instant firstSeenAt,
        Instant lastSeenAt
) {
}
