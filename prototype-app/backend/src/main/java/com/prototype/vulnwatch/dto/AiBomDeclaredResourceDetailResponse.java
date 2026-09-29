package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

/**
 * Everything the AI-BOM UI needs to explain one declared resource without a policy-violation
 * framing: which document declared it, what that document asserted about completeness, the
 * BOM component backing it, and whether projection has caught up to it.
 */
public record AiBomDeclaredResourceDetailResponse(
        AiBomDeclaredResourceResponse resource,
        String sourceBomType,
        String sourceState,
        long sourceRevision,
        Component component,
        Completeness completeness,
        Projection projection
) {
    public record Component(
            UUID componentId,
            String name,
            String version,
            String purl,
            String license,
            String scope,
            String componentType
    ) {
    }

    public record Completeness(
            String completeness,
            String assertedBy,
            Instant assertedAt
    ) {
    }

    public record Projection(
            boolean provenanceProjected,
            Instant provenanceProjectedAt,
            String bomFormat,
            String specVersion,
            String latestReceiptOperation,
            Instant latestReceiptCompletedAt
    ) {
    }
}
