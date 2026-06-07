package com.prototype.vulnwatch.dto;

public record FindingBacklogHealthResponse(
        long overdue,
        long dueSoon,
        long onTrack,
        long noSla
) {
}
