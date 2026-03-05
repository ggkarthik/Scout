package com.prototype.vulnwatch.dto;

import java.util.List;

public record ImpactedCvePageResponse(
        List<ImpactedCveRecordResponse> items,
        int page,
        int size,
        long totalItems,
        int totalPages
) {
}
