package com.prototype.vulnwatch.dto;

public record OperationalQualityDomainCountResponse(
        String domain,
        long issueCount
) {
}
