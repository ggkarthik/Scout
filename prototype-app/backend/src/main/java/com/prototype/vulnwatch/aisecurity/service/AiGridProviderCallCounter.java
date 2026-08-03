package com.prototype.vulnwatch.aisecurity.service;

import java.util.concurrent.atomic.AtomicLong;
import org.springframework.stereotype.Component;

/** Call-scoped counter shared by provider adapters; counts actual attempts, including retries. */
@Component
public class AiGridProviderCallCounter {
    private final ThreadLocal<AtomicLong> current = new ThreadLocal<>();

    public Measurement begin() {
        if (current.get() != null) throw new IllegalStateException("Provider-call measurement is already active");
        AtomicLong counter = new AtomicLong();
        current.set(counter);
        return new Measurement(counter);
    }

    public void increment() {
        AtomicLong counter = current.get();
        if (counter != null) counter.incrementAndGet();
    }

    public final class Measurement implements AutoCloseable {
        private final AtomicLong counter;
        private boolean closed;
        private Measurement(AtomicLong counter) { this.counter = counter; }
        public long count() { return counter.get(); }
        @Override public void close() {
            if (!closed) {
                current.remove();
                closed = true;
            }
        }
    }
}
