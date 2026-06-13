package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record BomEvidenceDocumentResponse(
        UUID bomId,
        UUID assetId,
        String bomType,
        String specFamily,
        String documentFormat,
        String sourceType,
        String sourceSystem,
        String sourceReference,
        String sourceLabel,
        String documentName,
        String checksumSha256,
        int componentCount,
        long evidenceCount,
        long vulnerabilityLinkCount,
        Instant ingestedAt
) {
}
