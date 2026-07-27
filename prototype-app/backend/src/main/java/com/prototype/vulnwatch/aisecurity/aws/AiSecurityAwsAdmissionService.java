package com.prototype.vulnwatch.aisecurity.aws;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class AiSecurityAwsAdmissionService {

    private final Semaphore global;
    private final ConcurrentHashMap<String, Semaphore> targets = new ConcurrentHashMap<>();
    private final int timeoutSeconds;

    public AiSecurityAwsAdmissionService(
            @Value("${app.ai-security.aws.max-concurrent:2}") int maxConcurrent,
            @Value("${app.ai-security.aws.admission-timeout-seconds:30}") int timeoutSeconds
    ) {
        this.global = new Semaphore(Math.max(1, maxConcurrent), true);
        this.timeoutSeconds = Math.max(1, timeoutSeconds);
    }

    public Permit acquire(String accountId, String region) {
        Semaphore target = targets.computeIfAbsent(accountId + ":" + region, ignored -> new Semaphore(1, true));
        boolean globalAcquired = false;
        try {
            globalAcquired = global.tryAcquire(timeoutSeconds, TimeUnit.SECONDS);
            if (!globalAcquired || !target.tryAcquire(timeoutSeconds, TimeUnit.SECONDS)) {
                if (globalAcquired) {
                    global.release();
                }
                throw new AdmissionException();
            }
            return new Permit(global, target);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            if (globalAcquired) {
                global.release();
            }
            throw new AdmissionException();
        }
    }

    public static final class Permit implements AutoCloseable {
        private final Semaphore global;
        private final Semaphore target;
        private boolean closed;

        private Permit(Semaphore global, Semaphore target) {
            this.global = global;
            this.target = target;
        }

        @Override
        public void close() {
            if (!closed) {
                closed = true;
                target.release();
                global.release();
            }
        }
    }

    public static final class AdmissionException extends RuntimeException {
        public AdmissionException() {
            super("AWS AI Security admission budget is currently exhausted");
        }
    }
}
