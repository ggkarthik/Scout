package com.prototype.vulnwatch.dto;

import java.util.List;

public record PlatformVulnRepoPageResponse(
        List<OrgSpecificCveExposureRecordResponse> items,
        int page,
        int size,
        long totalItems,
        int totalPages
) {
}
