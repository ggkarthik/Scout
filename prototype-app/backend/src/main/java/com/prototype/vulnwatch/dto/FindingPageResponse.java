package com.prototype.vulnwatch.dto;

import java.util.List;

public record FindingPageResponse(
        List<FindingResponse> items,
        int page,
        int size,
        long totalItems,
        int totalPages
) {
}
