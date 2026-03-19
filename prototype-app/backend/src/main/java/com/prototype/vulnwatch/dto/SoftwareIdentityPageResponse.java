package com.prototype.vulnwatch.dto;

import java.util.List;

public record SoftwareIdentityPageResponse(
        List<SoftwareIdentitySummaryResponse> content,
        int number,
        int size,
        long totalElements,
        int totalPages
) {
}
