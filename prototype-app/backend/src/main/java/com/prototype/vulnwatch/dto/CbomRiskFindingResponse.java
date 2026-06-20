package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record CbomRiskFindingResponse(
        UUID id,
        UUID componentId,
        String componentName,
        UUID assetId,
        String ruleId,
        String riskClass,
        String severity,
        String title,
        String detail,
        String evidence,
        String recommendation,
        String status,
        Instant firstSeenAt,
        Instant lastSeenAt
) {}
