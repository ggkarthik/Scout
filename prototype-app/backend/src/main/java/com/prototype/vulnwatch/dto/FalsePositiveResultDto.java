package com.prototype.vulnwatch.dto;

public record FalsePositiveResultDto(
        String id,
        String software,
        String version,
        boolean falsePositive,
        int notImpactedAssetCount,
        String vendorAdvisory,
        String vendorGuidance,
        String statusLabel,
        String statusDetail,
        String statusTone
) {}
