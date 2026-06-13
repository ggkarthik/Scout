package com.prototype.vulnwatch.dto;

import java.util.List;

public record BomComponentDetailResponse(
        String componentId,
        String packageName,
        String packageGroup,
        String version,
        String purl,
        String ecosystem,
        String license,
        String scope,
        String normalizedName,
        String eolSlug,
        String eolCycle,
        boolean isEol,
        String eolDate,
        String eolSupportEndDate,
        String supportPhase,
        String eolCheckedAt,
        String ingestedAt,
        String lastObservedAt,
        String assetId,
        String assetName,
        String assetIdentifier,
        String assetType,
        List<String> bomTypes,
        String correlationState,
        String riskLevel,
        int criticalCveCount,
        int highCveCount,
        int mediumCveCount,
        int lowCveCount,
        int totalCveCount,
        List<BomComponentCveSummary> cves,
        List<EolReleaseSummary> eolReleases
) {}
