package com.prototype.vulnwatch.dto;

import java.util.List;

public record OrgSpecificCveExposurePageResponse(
        List<OrgSpecificCveExposureRecordResponse> items,
        int page,
        int size,
        long totalItems,
        int totalPages
) {
}
