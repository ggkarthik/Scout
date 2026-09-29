package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class AiSecurityDigestBaselineServiceTest {
    @Test
    void distinguishesApprovalDriftRevocationAndKeyRotation() {
        assertEquals(AiSecurityDigestBaselineService.Outcome.UNAPPROVED,
                compare(null, "v1", "one"));
        assertEquals(AiSecurityDigestBaselineService.Outcome.UNAPPROVED,
                AiSecurityDigestBaselineService.comparison("REVOKED", "HMAC-SHA-256", "v1", "one",
                        "HMAC-SHA-256", "v1", "two"));
        assertEquals(AiSecurityDigestBaselineService.Outcome.UNCHANGED, compare("APPROVED", "v1", "one"));
        assertEquals(AiSecurityDigestBaselineService.Outcome.CHANGED_AFTER_APPROVAL,
                compare("APPROVED", "v1", "two"));
        assertEquals(AiSecurityDigestBaselineService.Outcome.BASELINE_UNKNOWN_REAPPROVAL_REQUIRED,
                compare("APPROVED", "v2", "two"));
    }

    private static AiSecurityDigestBaselineService.Outcome compare(String status, String observedVersion, String observedDigest) {
        return AiSecurityDigestBaselineService.comparison(status, "HMAC-SHA-256", "v1", "one",
                "HMAC-SHA-256", observedVersion, observedDigest);
    }
}
