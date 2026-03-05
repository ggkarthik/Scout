package com.prototype.vulnwatch.dto;

import java.util.List;

public record SoftwareModelPageResponse(
        List<SoftwareModelResponse> items,
        int page,
        int size,
        long totalItems,
        int totalPages
) {
}
