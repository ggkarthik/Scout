package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record HostSoftwareInstanceResponse(
        UUID id,
        UUID inventoryComponentId,
        String displayName,
        String publisher,
        String version,
        String normalizedPublisher,
        String normalizedProduct,
        String normalizedVersion,
        String sourceSystem,
        String versionEvidence,
        boolean activeInstall,
        boolean unlicensedInstall,
        Instant installDate,
        Instant lastScanned,
        Instant lastUsed,
        String discoveryModelPrimaryKey,
        String softwareIdentity,
        String cpe23,
        boolean needsVersionReview,
        boolean needsIdentityReview,
        boolean needsDiscoveryModelReview
) {
}
