package com.prototype.vulnwatch.client.http;

import java.util.Set;

public record OutboundPolicy(
        String providerKey,
        long minRequestIntervalMs,
        int maxRetries,
        long retryBaseBackoffMs,
        long maxBackoffMs,
        Set<Integer> retryableStatuses,
        boolean honorRetryAfter,
        boolean retryOnNetworkErrors
) {

    public OutboundPolicy {
        providerKey = providerKey == null ? "unknown" : providerKey.trim();
        minRequestIntervalMs = Math.max(0L, minRequestIntervalMs);
        maxRetries = Math.max(1, maxRetries);
        retryBaseBackoffMs = Math.max(0L, retryBaseBackoffMs);
        maxBackoffMs = Math.max(retryBaseBackoffMs, maxBackoffMs);
        retryableStatuses = retryableStatuses == null ? Set.of() : Set.copyOf(retryableStatuses);
    }

    public boolean isRetryableStatus(int statusCode) {
        return retryableStatuses.contains(statusCode);
    }

    public OutboundPolicy withRetryableStatuses(Set<Integer> statuses) {
        return new OutboundPolicy(
                providerKey,
                minRequestIntervalMs,
                maxRetries,
                retryBaseBackoffMs,
                maxBackoffMs,
                statuses,
                honorRetryAfter,
                retryOnNetworkErrors
        );
    }

    public OutboundPolicy withMaxBackoffMs(long value) {
        return new OutboundPolicy(
                providerKey,
                minRequestIntervalMs,
                maxRetries,
                retryBaseBackoffMs,
                value,
                retryableStatuses,
                honorRetryAfter,
                retryOnNetworkErrors
        );
    }
}
