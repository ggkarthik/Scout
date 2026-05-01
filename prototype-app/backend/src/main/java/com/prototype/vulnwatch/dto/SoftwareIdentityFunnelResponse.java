package com.prototype.vulnwatch.dto;

import java.time.Instant;

public record SoftwareIdentityFunnelResponse(
        long recordsFound,
        long uniqueSoftware,
        long softwareWithVulnerabilities,
        long softwareWithFindings,
        long sourceCount,
        Instant updatedAt
) {
}
