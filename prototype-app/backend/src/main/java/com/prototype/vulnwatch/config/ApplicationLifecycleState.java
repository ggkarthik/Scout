package com.prototype.vulnwatch.config;

import java.util.concurrent.atomic.AtomicBoolean;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Component
public class ApplicationLifecycleState {

    private final AtomicBoolean applicationReady = new AtomicBoolean(false);

    @EventListener(ApplicationReadyEvent.class)
    public void markApplicationReady() {
        applicationReady.set(true);
    }

    public boolean isApplicationReady() {
        return applicationReady.get();
    }
}
