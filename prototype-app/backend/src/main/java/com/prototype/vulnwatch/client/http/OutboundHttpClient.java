package com.prototype.vulnwatch.client.http;

import java.net.URI;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.LongSupplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import com.prototype.vulnwatch.util.LogUtil;

public class OutboundHttpClient {

    private static final Logger LOG = LoggerFactory.getLogger(OutboundHttpClient.class);

    private final RestTemplate restTemplate;
    private final LongSupplier currentTimeMillis;
    private final SleepStrategy sleepStrategy;
    private final ConcurrentHashMap<String, ProviderPacingState> pacingByProvider = new ConcurrentHashMap<>();

    public OutboundHttpClient(RestTemplate restTemplate) {
        this(
                restTemplate,
                System::currentTimeMillis,
                millis -> {
                    if (millis > 0) {
                        Thread.sleep(millis);
                    }
                }
        );
    }

    OutboundHttpClient(
            RestTemplate restTemplate,
            LongSupplier currentTimeMillis,
            SleepStrategy sleepStrategy
    ) {
        this.restTemplate = restTemplate;
        this.currentTimeMillis = currentTimeMillis;
        this.sleepStrategy = sleepStrategy;
    }

    public <T, E extends Exception> ResponseEntity<T> exchange(
            String endpoint,
            HttpMethod method,
            HttpEntity<?> requestEntity,
            Class<T> responseType,
            String operationName,
            OutboundPolicy policy,
            OutboundFailureClassifier<E> classifier
    ) throws E {
        return execute(
                endpoint,
                method,
                requestEntity,
                responseType,
                operationName,
                policy,
                classifier,
                response -> response
        );
    }

    public <T, R, E extends Exception> R execute(
            String endpoint,
            HttpMethod method,
            HttpEntity<?> requestEntity,
            Class<T> responseType,
            String operationName,
            OutboundPolicy policy,
            OutboundFailureClassifier<E> classifier,
            OutboundResponseHandler<T, R> responseHandler
    ) throws E {
        int attempts = Math.max(1, policy.maxRetries());
        for (int attempt = 1; attempt <= attempts; attempt++) {
            try {
                ResponseEntity<T> response = performExchange(endpoint, method, requestEntity, responseType, policy);
                return responseHandler.handle(response);
            } catch (Exception error) {
                OutboundFailureContext context = new OutboundFailureContext(
                        endpoint,
                        operationName,
                        policy,
                        error,
                        attempt,
                        attempts
                );
                OutboundFailureDecision<E> decision = classifier.classify(context);
                boolean lastAttempt = attempt >= attempts;
                if (!decision.retryable() || lastAttempt) {
                    E terminalException = decision.terminalException();
                    logTerminal(context, terminalException);
                    throw terminalException;
                }
                long delayMs = decision.retryDelayMs() != null
                        ? Math.max(0L, decision.retryDelayMs())
                        : computeBackoffDelayMs(policy, attempt);
                LOG.warn(
                        "Outbound HTTP retry provider={} operation={} attempt={}/{} status={} delayMs={} endpoint={}",
                        policy.providerKey(),
                        operationName,
                        attempt,
                        attempts,
                        describeStatus(context),
                        delayMs,
                        LogUtil.safe(endpoint)
                );
                sleep(delayMs, policy.providerKey(), operationName);
            }
        }
        throw new IllegalStateException("Outbound retry loop exhausted without terminal exception");
    }

    private <T> ResponseEntity<T> performExchange(
            String endpoint,
            HttpMethod method,
            HttpEntity<?> requestEntity,
            Class<T> responseType,
            OutboundPolicy policy
    ) {
        ProviderPacingState state = pacingByProvider.computeIfAbsent(policy.providerKey(), ignored -> new ProviderPacingState());
        state.lock.lock();
        try {
            long waitMs = waitTimeMs(state.hasCompletedRequest, state.lastRequestCompletedAtMs, policy.minRequestIntervalMs());
            sleep(waitMs, policy.providerKey(), "request pacing");
            try {
                URI uri = URI.create(endpoint);
                String scheme = uri.getScheme();
                if (scheme == null || (!scheme.equalsIgnoreCase("https") && !scheme.equalsIgnoreCase("http"))) {
                    throw new IllegalArgumentException("Outbound requests must use http or https: " + endpoint);
                }
                return restTemplate.exchange(uri, method, requestEntity, responseType);
            } finally {
                state.lastRequestCompletedAtMs = currentTimeMillis.getAsLong();
                state.hasCompletedRequest = true;
            }
        } finally {
            state.lock.unlock();
        }
    }

    private long waitTimeMs(boolean hasCompletedRequest, long lastRequestCompletedAtMs, long minRequestIntervalMs) {
        if (minRequestIntervalMs <= 0L) {
            return 0L;
        }
        if (!hasCompletedRequest) {
            return 0L;
        }
        long now = currentTimeMillis.getAsLong();
        long elapsed = now - lastRequestCompletedAtMs;
        return Math.max(0L, minRequestIntervalMs - elapsed);
    }

    private long computeBackoffDelayMs(OutboundPolicy policy, int attempt) {
        long base = Math.max(0L, policy.retryBaseBackoffMs());
        if (base == 0L) {
            return 0L;
        }
        long exponent = 1L << Math.min(6, Math.max(0, attempt - 1));
        long candidate = Math.multiplyExact(base, exponent);
        long jitterUpperBound = Math.max(25L, Math.min(1000L, base));
        long jitter = jitterUpperBound <= 0L ? 0L : java.util.concurrent.ThreadLocalRandom.current().nextLong(jitterUpperBound + 1L);
        long bounded = Math.min(Long.MAX_VALUE - jitter, candidate) + jitter;
        return Math.min(policy.maxBackoffMs(), bounded);
    }

    private void logTerminal(OutboundFailureContext context, Exception terminalException) {
        LOG.warn(
                "Outbound HTTP terminal failure provider={} operation={} attempt={}/{} status={} endpoint={}",
                context.policy().providerKey(),
                context.operationName(),
                context.attempt(),
                context.maxAttempts(),
                describeStatus(context),
                LogUtil.safe(context.endpoint()),
                terminalException
        );
    }

    private String describeStatus(OutboundFailureContext context) {
        Integer status = context.statusCodeValue();
        if (status != null) {
            return Integer.toString(status);
        }
        return context.isNetworkAccessError() ? "NETWORK" : "CLIENT_EXCEPTION";
    }

    private void sleep(long millis, String providerKey, String operationName) {
        if (millis <= 0L) {
            return;
        }
        try {
            sleepStrategy.sleep(millis);
        } catch (InterruptedException interruptedException) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(
                    "Interrupted while waiting for outbound HTTP " + operationName + " (" + providerKey + ")",
                    interruptedException
            );
        }
    }

    @FunctionalInterface
    interface SleepStrategy {
        void sleep(long millis) throws InterruptedException;
    }

    private static final class ProviderPacingState {
        private final ReentrantLock lock = new ReentrantLock();
        private volatile boolean hasCompletedRequest = false;
        private volatile long lastRequestCompletedAtMs = 0L;
    }
}
