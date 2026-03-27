package com.prototype.vulnwatch.client.http;

public record OutboundPolicyDefaults(
        long minRequestIntervalMs,
        int maxRetries,
        long retryBaseBackoffMs,
        long maxBackoffMs,
        boolean honorRetryAfter,
        boolean retryOnNetworkErrors
) {
}
