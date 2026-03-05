package com.prototype.vulnwatch.dto;

public record AdvisoryRuleRequest(
        String ecosystem,
        String packageName,
        String versionExact,
        String versionStart,
        String versionEnd,
        String digest,
        String cpe
) {
    public AdvisoryRuleRequest(
            String ecosystem,
            String packageName,
            String versionExact,
            String versionStart,
            String versionEnd,
            String digest
    ) {
        this(ecosystem, packageName, versionExact, versionStart, versionEnd, digest, null);
    }
}
