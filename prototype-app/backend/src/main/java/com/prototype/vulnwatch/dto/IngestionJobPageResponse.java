package com.prototype.vulnwatch.dto;

import java.util.List;

public record IngestionJobPageResponse(
        List<IngestionJobResponse> items,
        int page,
        int size,
        long totalItems,
        int totalPages
) {
}
