package com.prototype.vulnwatch.security;

public class PublicRateLimitException extends RuntimeException {
    private final long retryAfterSeconds;

    public PublicRateLimitException(long retryAfterSeconds) {
        super("Too many attempts. Please wait and try again.");
        this.retryAfterSeconds = Math.max(1, retryAfterSeconds);
    }

    public long getRetryAfterSeconds() {
        return retryAfterSeconds;
    }
}
