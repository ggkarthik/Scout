package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record SbomUploadEvidenceResponse(
        UUID id,
        UUID assetId,
        String assetName,
        String assetIdentifier,
        String assetType,
        String status,
        String format,
        Instant uploadedAt,
        String originalFilename,
        String ingestionSourceType,
        String ingestionSourceSystem,
        String sourceReference,
        String sourceEndpoint,
        Integer fetchStatusCode,
        String contentType,
        Long contentLengthBytes,
        String contentSha256,
        Integer componentCount,
        Integer findingsGenerated,
        String evidenceJson
) {
}
