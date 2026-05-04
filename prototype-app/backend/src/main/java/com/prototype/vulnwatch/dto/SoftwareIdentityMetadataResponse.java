package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record SoftwareIdentityMetadataResponse(
        UUID softwareIdentityId,
        String owner,
        String licensed,
        String licenseType,
        String supportGroup,
        String recommendation,
        Instant recommendationUpdatedAt,
        Instant updatedAt
) {
}
