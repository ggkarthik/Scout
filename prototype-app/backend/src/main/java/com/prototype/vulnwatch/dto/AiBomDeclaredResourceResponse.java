package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

/** A declared AI-BOM resource (model or dataset) and its current deployment-linking state. */
public record AiBomDeclaredResourceResponse(
        UUID id,
        UUID sourceId,
        UUID bomId,
        UUID bomComponentId,
        String resourceKind,
        String name,
        String version,
        String identityKind,
        String identityValue,
        String deploymentState,
        UUID linkedArtifactId,
        String linkMethod,
        String linkReviewedBy,
        Instant linkReviewedAt,
        UUID proposedArtifactId,
        String proposedBy,
        Instant proposedAt,
        Instant firstDeclaredAt,
        Instant lastDeclaredAt
) {
}
