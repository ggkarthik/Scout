package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record BomDetailResponse(
        UUID id,
        UUID assetId,
        String bomType,
        String format,
        String formatVersion,
        String specFamily,
        String documentFormat,
        String serialNumber,
        String supplier,
        String sourceMethod,
        String sourceType,
        String sourceSystem,
        String sourceReference,
        String sourceUrl,
        String checksumSha256,
        BomInspectionResponse inspection,
        int componentCount,
        long evidenceCount,
        long vulnerabilityLinkCount,
        long correlatedComponentCount,
        String status,
        Instant ingestedAt,
        String ingestedBy,
        List<BomWorkflowSummaryResponse> workflowSummary,
        List<BomComponentResponse> components
) {}
