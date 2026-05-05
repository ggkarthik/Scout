package com.prototype.vulnwatch.domain;

/**
 * Organisation-level impact classification for a CVE record.
 * Computed from CVSS severity, exploitability signals (KEV/EPSS),
 * and a server-side approximation of the S.AI risk score.
 */
public enum OrgImpact {
    NONE,
    LOW,
    MEDIUM,
    HIGH
}
