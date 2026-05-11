package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record FixRecordResponse(
        UUID id,
        String cveId,
        List<String> relatedCveIds,
        String summary,
        String description,
        String fixType,
        List<SoftwareEntity> softwareEntities,
        String osHint,
        String recommendationSource,
        List<String> sourceUrls,
        Instant generatedAt,
        Instant createdAt
) {
    public record SoftwareEntity(
            String name,
            String ecosystem,
            String version,
            int assetCount
    ) {}
}
