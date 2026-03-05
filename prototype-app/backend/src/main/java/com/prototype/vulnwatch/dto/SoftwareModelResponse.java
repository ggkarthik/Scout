package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record SoftwareModelResponse(
        UUID id,
        String normalizedKey,
        String canonicalPublisher,
        String canonicalProduct,
        String primaryIdentifierType,
        String primaryIdentifier,
        int totalComponents,
        int activeComponents,
        int assetsRepresented,
        Instant createdAt,
        Instant updatedAt
) {
}
