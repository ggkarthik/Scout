package com.prototype.vulnwatch.dto;

import java.time.LocalDate;

public record FindingQueueAnalyticsTrendPointResponse(
        LocalDate date,
        long openedCount,
        long resolvedCount,
        long reopenedCount
) {
}
