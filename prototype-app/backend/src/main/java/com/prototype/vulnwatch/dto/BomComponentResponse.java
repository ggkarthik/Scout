package com.prototype.vulnwatch.dto;

import java.util.UUID;

public record BomComponentResponse(
        UUID id,
        String name,
        String version,
        String purl,
        String cpe,
        String license,
        String supplier,
        String componentType,
        String category,
        String workflowStatus,
        int vulnerabilityCount,
        int evidenceCount,
        boolean active
) {}
