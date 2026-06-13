package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record BomLineageItemResponse(
        UUID id,
        UUID previousBomId,
        UUID supersededBy,
        String bomType,
        String status,
        String format,
        String formatVersion,
        String specFamily,
        String documentFormat,
        String sourceType,
        String sourceSystem,
        String sourceReference,
        String checksumSha256,
        int componentCount,
        Instant ingestedAt
) {}
