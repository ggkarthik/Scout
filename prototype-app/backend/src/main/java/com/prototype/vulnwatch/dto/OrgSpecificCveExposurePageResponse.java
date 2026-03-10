package com.prototype.vulnwatch.dto;

import java.util.List;

public record OrgSpecificCveExposurePageResponse(
        OrgSpecificCveExposureSummaryResponse summary,
        List<OrgSpecificCveExposureRecordResponse> items,
        int page,
        int size,
        long totalItems,
        int totalPages
) {
}
