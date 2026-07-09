package com.prototype.vulnwatch.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;
import org.springframework.util.ErrorHandler;

/**
 * Resilient task scheduler shared by every {@code @Scheduled} method.
 *
 * <p>Spring's default scheduler is a single-threaded {@code ScheduledThreadPoolExecutor}, which has
 * two failure modes that have bitten this app:
 *
 * <ol>
 *   <li>All scheduled tasks share one thread, so a slow daily sync delays the 2-second ingestion-job
 *       poller and finding-delta drain.</li>
 *   <li>When a periodic task throws an exception that propagates out, {@code ReschedulingRunnable}
 *       never reaches its reschedule step, so the task dies silently for the rest of the JVM's life.
 *       The ingestion-job poller died exactly this way after a transient DB error during a host
 *       sleep/clock-leap window, leaving GitHub SBOM runs stuck in QUEUED.</li>
 * </ol>
 *
 * <p>This bean gives the scheduler a small pool so tasks don't starve each other, and installs an
 * error handler that logs and swallows so a throwing task is always rescheduled and keeps running.
 */
@Configuration
@EnableScheduling
@ConditionalOnProperty(name = "app.scheduling.enabled", havingValue = "true", matchIfMissing = true)
public class SchedulingConfig {

    private static final Logger LOG = LoggerFactory.getLogger(SchedulingConfig.class);

    @Bean
    public ThreadPoolTaskScheduler taskScheduler() {
        ThreadPoolTaskScheduler scheduler = new ThreadPoolTaskScheduler();
        scheduler.setPoolSize(4);
        scheduler.setThreadNamePrefix("scheduling-");
        scheduler.setErrorHandler(loggingErrorHandler());
        return scheduler;
    }

    /**
     * Logs the failure and suppresses it, so {@code ReschedulingRunnable} reschedules the next run
     * instead of letting the periodic task die.
     */
    static ErrorHandler loggingErrorHandler() {
        return throwable ->
                LOG.error("Scheduled task threw an exception; it will be rescheduled and continue", throwable);
    }
}
