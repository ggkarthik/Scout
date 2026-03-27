package com.prototype.vulnwatch.client.http;

import java.util.LinkedHashSet;
import java.util.Set;

public class OutboundPolicyFactory {

    private static final Set<Integer> STANDARD_RETRYABLE_STATUSES = buildStandardRetryableStatuses();

    private final OutboundPolicyDefaults defaults;

    public OutboundPolicyFactory(OutboundPolicyDefaults defaults) {
        this.defaults = defaults;
    }

    public OutboundPolicy forProvider(
            String providerKey,
            Long minRequestIntervalMs,
            Integer maxRetries,
            Long retryBaseBackoffMs
    ) {
        return new OutboundPolicy(
                providerKey,
                minRequestIntervalMs == null ? defaults.minRequestIntervalMs() : minRequestIntervalMs,
                maxRetries == null ? defaults.maxRetries() : maxRetries,
                retryBaseBackoffMs == null ? defaults.retryBaseBackoffMs() : retryBaseBackoffMs,
                defaults.maxBackoffMs(),
                STANDARD_RETRYABLE_STATUSES,
                defaults.honorRetryAfter(),
                defaults.retryOnNetworkErrors()
        );
    }

    private static Set<Integer> buildStandardRetryableStatuses() {
        Set<Integer> codes = new LinkedHashSet<>();
        codes.add(408);
        codes.add(429);
        for (int code = 500; code <= 599; code++) {
            codes.add(code);
        }
        return Set.copyOf(codes);
    }
}
