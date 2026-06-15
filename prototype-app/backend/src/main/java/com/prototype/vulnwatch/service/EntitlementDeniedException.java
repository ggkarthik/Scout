package com.prototype.vulnwatch.service;

public class EntitlementDeniedException extends RuntimeException {

    private final String code;
    private final String entitlementKey;
    private final String currentPlan;

    public EntitlementDeniedException(String entitlementKey, String currentPlan, String message) {
        super(message);
        this.code = "PLAN_UPGRADE_REQUIRED";
        this.entitlementKey = entitlementKey;
        this.currentPlan = currentPlan;
    }

    public String getCode() {
        return code;
    }

    public String getEntitlementKey() {
        return entitlementKey;
    }

    public String getCurrentPlan() {
        return currentPlan;
    }
}
