package com.prototype.vulnwatch.dto;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

public record CbomPostureSummaryResponse(
        UUID id,
        UUID assetId,
        String assetName,
        UUID lastSourceBomId,
        int totalComponents,
        int criticalFindings,
        int highFindings,
        int mediumFindings,
        int lowFindings,
        int infoFindings,
        int acceptedFindings,
        int quantumVulnerable,
        int weakAlgorithms,
        int expiringCerts,
        BigDecimal postureScore,
        Instant lastEvaluatedAt
) {}
