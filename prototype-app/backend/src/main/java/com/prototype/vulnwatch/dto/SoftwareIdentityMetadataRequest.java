package com.prototype.vulnwatch.dto;

public record SoftwareIdentityMetadataRequest(
        String owner,
        String licensed,
        String licenseType,
        String supportGroup,
        String recommendation
) {
}
