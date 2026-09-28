package com.prototype.vulnwatch.dto;

import java.util.List;

public record BomComponentSummaryResponse(
        String componentId,
        String packageName,
        String version,
        String purl,
        String ecosystem,
        String license,
        String assetId,
        String assetName,
        List<String> bomTypes,
        boolean isEol,
        String eolDate,
        int criticalCveCount,
        int highCveCount,
        int mediumCveCount,
        int lowCveCount,
        int totalCveCount,
        String correlationState,
        String riskLevel,
        int findingCount,
        int criticalFindingCount,
        int highFindingCount,
        // What BOM evidence says about this component's presence: SUPPORTED, CONFLICTING,
        // WITHDRAWN or LEGACY_UNKNOWN. Distinct from its ACTIVE/RETIRED status, which is
        // presence itself. CONFLICTING in particular needs a human to adjudicate, so it has
        // to be visible.
        String bomEvidenceState
) {}
