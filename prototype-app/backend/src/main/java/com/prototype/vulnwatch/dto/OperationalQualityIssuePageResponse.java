package com.prototype.vulnwatch.dto;

import java.util.List;

public record OperationalQualityIssuePageResponse(
        List<OperationalQualityIssueResponse> items,
        int page,
        int size,
        long totalItems,
        int totalPages
) {
}
