package com.prototype.vulnwatch.aisecurity.copilot;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.BackgroundTaskExecutionPolicy;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantService;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.scheduling.support.CronExpression;
import org.springframework.stereotype.Service;

/** Runs tenant-configured Copilot schedules with discovery and runtime failure isolation. */
@Service
public class CopilotStudioScheduleService {
    private static final Logger LOG = LoggerFactory.getLogger(CopilotStudioScheduleService.class);
    private final TenantService tenants;
    private final CopilotStudioConnectorService configs;
    private final CopilotStudioRuntimeCollectionService runtime;
    private final boolean enabled;
    private final Map<UUID, Instant> lastFire = new ConcurrentHashMap<>();
    private BackgroundTaskExecutionPolicy backgroundTasks = BackgroundTaskExecutionPolicy.allowAll();

    public CopilotStudioScheduleService(TenantService tenants, CopilotStudioConnectorService configs,
                                        CopilotStudioRuntimeCollectionService runtime,
                                        @Value("${app.ai-security.copilot.enabled:false}") boolean enabled) {
        this.tenants = tenants;
        this.configs = configs;
        this.runtime = runtime;
        this.enabled = enabled;
    }

    @Autowired
    public void setBackgroundTasks(BackgroundTaskExecutionPolicy backgroundTasks) {
        this.backgroundTasks = backgroundTasks == null ? BackgroundTaskExecutionPolicy.allowAll() : backgroundTasks;
    }

    @Scheduled(fixedDelayString = "${app.ai-security.copilot.schedule-poll-ms:60000}")
    public void poll() {
        if (!enabled || !backgroundTasks.allowsBackgroundTask("ai-security.copilot-schedule")) return;
        TenantContext.runAsPlatform(() -> tenants.listActiveTenants().forEach(this::pollTenant));
    }

    void pollTenant(Tenant tenant) {
        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC).withNano(0);
        for (CopilotStudioConnectorService.Response config : configs.list(tenant)) {
            if (config.killSwitch() || (!config.discoveryEnabled() && !config.executionEnabled())) continue;
            Instant due = dueTime(config.scheduleCron(), now);
            if (due == null || due.equals(lastFire.put(config.id(), due))) continue;
            if (config.discoveryEnabled()) runSafely("discovery", tenant, config.id(),
                    () -> configs.trigger(tenant, config.id(), "copilot-studio-schedule"));
            if (config.executionEnabled()) runSafely("runtime", tenant, config.id(),
                    () -> runtime.run(tenant, config.id()));
        }
        lastFire.entrySet().removeIf(entry -> entry.getValue().isBefore(now.minusDays(2).toInstant()));
    }

    private static Instant dueTime(String cron, ZonedDateTime now) {
        try {
            ZonedDateTime next = CronExpression.parse(cron).next(now.minusSeconds(61));
            return next != null && !next.isAfter(now) ? next.toInstant() : null;
        } catch (IllegalArgumentException invalidCron) {
            return null;
        }
    }

    private void runSafely(String source, Tenant tenant, UUID connectorId, Runnable operation) {
        try { operation.run(); }
        catch (RuntimeException error) {
            LOG.warn("Copilot {} schedule failed tenant={} connector={} type={}",
                    source, tenant.getId(), connectorId, error.getClass().getSimpleName());
        }
    }
}
