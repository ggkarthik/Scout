package com.prototype.vulnwatch.dto;

import java.util.UUID;

public record BomEvidenceComponentResponse(
        UUID componentId,
        UUID bomId,
        String name,
        String version,
        String supplier,
        String purl,
        String cpe,
        String license,
        String workflowStatus,
        long evidenceCount,
        long vulnerabilityCount,
        String sourceSystem,
        String sourceReference
) {
}
