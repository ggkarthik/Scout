package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;

/**
 * BLG-014: SLO status snapshot returned by GET /api/slo/status.
 */
public record SloStatusResponse(
        Instant evaluatedAt,
        boolean overallCompliant,
        List<SloEntry> slos
) {
    public record SloEntry(
            String name,
            String description,
            String unit,
            double target,
            double current,
            boolean compliant,
            String window
    ) {
    }
}
