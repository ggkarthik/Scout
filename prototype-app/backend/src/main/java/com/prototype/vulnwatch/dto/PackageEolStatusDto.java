package com.prototype.vulnwatch.dto;

import java.time.LocalDate;

public record PackageEolStatusDto(
        String packageName,
        String ecosystem,
        String eolSlug,
        String eolCycle,
        LocalDate eolDate,
        Boolean isEol,
        Integer eolDaysRemaining,
        long assetCount
) {
}
