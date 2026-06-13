package com.prototype.vulnwatch.dto;

import java.util.UUID;

public record BomIngestionResultResponse(
        UUID bomId,
        UUID assetId,
        String bomType,
        String format,
        String formatVersion,
        String specFamily,
        String documentFormat,
        String supportLevel,
        boolean supported,
        java.util.List<String> warnings,
        int componentCount,
        int findingsGenerated,
        String status,
        String action
) {}
