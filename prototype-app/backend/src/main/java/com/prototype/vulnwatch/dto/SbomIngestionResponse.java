package com.prototype.vulnwatch.dto;

import java.util.UUID;

public record SbomIngestionResponse(
        UUID assetId,
        UUID sbomUploadId,
        int componentsIngested,
        int findingsGenerated
) {
}
