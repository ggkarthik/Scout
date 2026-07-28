package com.prototype.vulnwatch.aisecurity.azure;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class AiSecurityAzureAdmissionService {

    private final Semaphore global;
    private final ConcurrentHashMap<String, Semaphore> subscriptions = new ConcurrentHashMap<>();
    private final int perSubscription;
    private final Duration timeout;
    private AiSecurityAzureMetrics metrics;

    public AiSecurityAzureAdmissionService(
            @Value("${app.ai-security.azure.max-concurrent:2}") int maxConcurrent,
            @Value("${app.ai-security.azure.max-concurrent-per-subscription:1}") int perSubscription,
            @Value("${app.ai-security.azure.admission-timeout-seconds:30}") int timeoutSeconds
    ) {
        this.global = new Semaphore(Math.max(1, maxConcurrent), true);
        this.perSubscription = Math.max(1, perSubscription);
        this.timeout = Duration.ofSeconds(Math.max(1, timeoutSeconds));
    }

    @Autowired
    void setMetrics(AiSecurityAzureMetrics metrics) {
        this.metrics = metrics;
    }

    public Permit acquire(String subscriptionId) {
        if (subscriptionId == null || subscriptionId.isBlank()) {
            record("invalid");
            throw new AdmissionException("Azure subscription is required for admission");
        }
        Semaphore subscription = subscriptions.computeIfAbsent(
                subscriptionId.toLowerCase(), ignored -> new Semaphore(perSubscription, true));
        boolean globalAcquired = false;
        try {
            if (!global.tryAcquire(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
                record("global_timeout");
                throw new AdmissionException("Azure AI Security global admission timed out");
            }
            globalAcquired = true;
            if (!subscription.tryAcquire(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
                global.release();
                globalAcquired = false;
                record("subscription_timeout");
                throw new AdmissionException("Azure AI Security subscription admission timed out");
            }
            record("granted");
            return new Permit(global, subscription);
        } catch (InterruptedException exception) {
            if (globalAcquired) {
                global.release();
            }
            Thread.currentThread().interrupt();
            record("interrupted");
            throw new AdmissionException("Azure AI Security admission was interrupted");
        }
    }

    private void record(String outcome) {
        if (metrics != null) {
            metrics.recordAdmission(outcome);
        }
    }

    public static final class Permit implements AutoCloseable {
        private final Semaphore global;
        private final Semaphore subscription;
        private boolean closed;

        private Permit(Semaphore global, Semaphore subscription) {
            this.global = global;
            this.subscription = subscription;
        }

        @Override
        public void close() {
            if (!closed) {
                subscription.release();
                global.release();
                closed = true;
            }
        }
    }

    public static class AdmissionException extends RuntimeException {
        public AdmissionException(String message) {
            super(message);
        }
    }
}
