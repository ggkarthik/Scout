package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.Map;

public record SavedCveInvestigationSummaryResponse(
        String mode,
        Instant generatedAt,
        Map<String, Object> input,
        CveInvestigationSummaryResponse summary
) {
}
