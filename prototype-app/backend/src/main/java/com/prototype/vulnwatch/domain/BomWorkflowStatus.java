package com.prototype.vulnwatch.domain;

public enum BomWorkflowStatus {
    DISCOVERED,
    CORRELATED,
    UNDER_INVESTIGATION,
    PATCH_AVAILABLE,
    REMEDIATION_OPEN,
    RESOLVED,
    ACCEPTED_RISK,
    FALSE_POSITIVE
}
