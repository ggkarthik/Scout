package com.prototype.vulnwatch.service;

public class QuotaExceededException extends RuntimeException {

    private final String quotaCode;

    public QuotaExceededException(String quotaCode, String message) {
        super(message);
        this.quotaCode = quotaCode;
    }

    public String getQuotaCode() {
        return quotaCode;
    }
}
