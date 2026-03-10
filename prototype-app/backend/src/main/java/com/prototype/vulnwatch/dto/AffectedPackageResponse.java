package com.prototype.vulnwatch.dto;

public record AffectedPackageResponse(
        String ecosystem,
        String packageName,
        String affectedVersions,
        String fixedVersion,
        String cpe,
        String vexStatus
) {
}
