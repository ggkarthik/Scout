package com.prototype.vulnwatch.dto;

import java.time.LocalDate;
import java.util.UUID;

public record ComponentEolStatusDto(
        UUID componentId,
        String packageName,
        String ecosystem,
        String version,
        String assetName,
        String eolSlug,
        String eolCycle,
        LocalDate eolDate,
        Boolean isEol,
        Integer eolDaysRemaining,
        LocalDate eolSupportEndDate
) {
}
