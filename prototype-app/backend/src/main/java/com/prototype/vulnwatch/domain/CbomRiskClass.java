package com.prototype.vulnwatch.domain;

public enum CbomRiskClass {
    WEAK_ALGORITHM,
    DEPRECATED_PROTOCOL,
    CERT_EXPIRY,
    QUANTUM_VULNERABLE,
    CREDENTIAL_EXPOSURE,
    KEY_MANAGEMENT,
    MISSING_ROTATION,
    STORAGE_RISK
}
