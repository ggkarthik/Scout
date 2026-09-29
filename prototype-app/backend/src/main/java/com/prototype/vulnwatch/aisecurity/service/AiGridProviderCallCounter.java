package com.prototype.vulnwatch.aisecurity.service;

import java.util.concurrent.atomic.AtomicLong;
import org.springframework.stereotype.Component;

/** Call-scoped counter shared by provider adapters; counts actual attempts, including retries. */
@Component
public class AiGridProviderCallCounter {
    private final ThreadLocal<State> current = new ThreadLocal<>();

    public Measurement begin() {
        return begin(Long.MAX_VALUE);
    }

    public Measurement begin(long ceiling) {
        if (ceiling < 1) throw new IllegalArgumentException("Provider-call ceiling must be positive");
        if (current.get() != null) throw new IllegalStateException("Provider-call measurement is already active");
        State state = new State(new AtomicLong(), ceiling);
        current.set(state);
        return new Measurement(state);
    }

    /** Invoked immediately before every provider transmission, including SDK retries. */
    public void increment() {
        State state = current.get();
        if (state == null) return;
        long currentCount = state.counter().get();
        if (currentCount >= state.ceiling()) {
            throw new ProviderCallBudgetExceededException(state.ceiling());
        }
        state.counter().incrementAndGet();
    }

    public final class Measurement implements AutoCloseable {
        private final State state;
        private boolean closed;
        private Measurement(State state) { this.state = state; }
        public long count() { return state.counter().get(); }
        public long ceiling() { return state.ceiling(); }
        @Override public void close() {
            if (!closed) {
                current.remove();
                closed = true;
            }
        }
    }

    private record State(AtomicLong counter, long ceiling) { }

    public static final class ProviderCallBudgetExceededException extends RuntimeException {
        private final long ceiling;
        public ProviderCallBudgetExceededException(long ceiling) {
            super("Provider-call ceiling exhausted");
            this.ceiling = ceiling;
        }
        public long ceiling() { return ceiling; }
    }
}
