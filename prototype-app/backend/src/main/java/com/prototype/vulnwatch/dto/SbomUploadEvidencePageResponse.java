package com.prototype.vulnwatch.dto;

import java.util.List;

public record SbomUploadEvidencePageResponse(
        List<SbomUploadEvidenceResponse> items,
        int page,
        int size,
        long totalItems,
        int totalPages
) {
}
