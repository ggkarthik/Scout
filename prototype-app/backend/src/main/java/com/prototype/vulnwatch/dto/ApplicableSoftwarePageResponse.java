package com.prototype.vulnwatch.dto;

import java.util.List;

public record ApplicableSoftwarePageResponse(
        List<ApplicableSoftwareRecordResponse> items,
        int page,
        int size,
        long totalItems,
        int totalPages
) {
}
