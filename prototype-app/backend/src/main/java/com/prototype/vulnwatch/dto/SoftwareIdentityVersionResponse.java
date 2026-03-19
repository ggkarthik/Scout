package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.time.LocalDate;

public record SoftwareIdentityVersionResponse(
        String version,
        String eolSlug,
        String eolCycle,
        LocalDate eolDate,
        Boolean isEol,
        Integer eolDaysRemaining,
        long assetCount,
        long componentCount,
        long openFindingCount,
        long openVulnerabilityCount,
        Instant lastObservedAt
) {
}
