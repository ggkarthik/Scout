package com.prototype.vulnwatch.service;

public class QuotaExceededException extends RuntimeException {

    private final String quotaCode;
    private final Integer retryAfterSeconds;

    public QuotaExceededException(String quotaCode, String message) {
        this(quotaCode, message, null);
    }

    public QuotaExceededException(String quotaCode, String message, Integer retryAfterSeconds) {
        super(message);
        this.quotaCode = quotaCode;
        this.retryAfterSeconds = retryAfterSeconds;
    }

    public String getQuotaCode() {
        return quotaCode;
    }

    public Integer getRetryAfterSeconds() {
        return retryAfterSeconds;
    }
}
