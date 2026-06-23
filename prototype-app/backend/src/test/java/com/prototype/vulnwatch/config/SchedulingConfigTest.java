package com.prototype.vulnwatch.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import org.junit.jupiter.api.Test;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;

class SchedulingConfigTest {

    @Test
    void taskSchedulerUsesMultipleThreads() {
        ThreadPoolTaskScheduler scheduler = new SchedulingConfig().taskScheduler();
        scheduler.initialize();
        try {
            assertThat(scheduler.getScheduledThreadPoolExecutor().getCorePoolSize()).isGreaterThan(1);
        } finally {
            scheduler.shutdown();
        }
    }

    @Test
    void errorHandlerSwallowsExceptionSoTaskIsRescheduled() {
        assertThatCode(() ->
                SchedulingConfig.loggingErrorHandler().handleError(new IllegalStateException("boom")))
                .doesNotThrowAnyException();
    }
}
