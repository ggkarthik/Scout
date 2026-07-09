package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import jakarta.annotation.PostConstruct;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Service
public class FindingProjectionMaintenanceService {

    private static final Logger LOG = LoggerFactory.getLogger(FindingProjectionMaintenanceService.class);

    private final TenantService tenantService;
    private final FindingListProjectionService findingListProjectionService;
    private final long projectionStaleThresholdMinutes;
    private BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy = BackgroundTaskExecutionPolicy.allowAll();

    public FindingProjectionMaintenanceService(
            TenantService tenantService,
            FindingListProjectionService findingListProjectionService,
            @Value("${app.slo.projection-stale-threshold-minutes:15}") long projectionStaleThresholdMinutes
    ) {
        this.tenantService = tenantService;
        this.findingListProjectionService = findingListProjectionService;
        this.projectionStaleThresholdMinutes = projectionStaleThresholdMinutes;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy) {
        this.backgroundTaskExecutionPolicy = backgroundTaskExecutionPolicy == null
                ? BackgroundTaskExecutionPolicy.allowAll()
                : backgroundTaskExecutionPolicy;
    }

    @PostConstruct
    public void refreshStaleProjectionsOnStartup() {
        if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("finding-projection-maintenance.startup-refresh")) {
            return;
        }
        int refreshed = refreshStaleProjections();
        if (refreshed > 0) {
            LOG.warn("Refreshed {} stale finding projections during startup recovery", refreshed);
        }
    }

    @Scheduled(fixedDelayString = "${app.findings.projection-maintenance-interval-ms:300000}")
    public void refreshStaleProjectionsOnSchedule() {
        if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("finding-projection-maintenance.scheduled-refresh")) {
            return;
        }
        try {
            int refreshed = refreshStaleProjections();
            if (refreshed > 0) {
                LOG.warn("Refreshed {} stale finding projections during scheduled maintenance", refreshed);
            }
        } catch (Exception ex) {
            LOG.warn("Finding projection maintenance failed: {}", ex.getMessage(), ex);
        }
    }

    int refreshStaleProjections() {
        return TenantContext.runAsPlatform(() -> {
            Instant staleBefore = Instant.now().minus(projectionStaleThresholdMinutes, ChronoUnit.MINUTES);
            int refreshed = 0;
            for (Tenant tenant : tenantService.listActiveTenants()) {
                try {
                    FindingListProjectionService.ProjectionStatus status = findingListProjectionService.inspectProjectionStatus(tenant);
                    if (!requiresRefresh(status, staleBefore)) {
                        continue;
                    }
                    findingListProjectionService.refreshTenant(tenant);
                    refreshed += 1;
                } catch (Exception ex) {
                    LOG.warn("Finding projection maintenance failed for tenant {}: {}", tenant.getId(), ex.getMessage(), ex);
                }
            }
            return refreshed;
        });
    }

    private boolean requiresRefresh(FindingListProjectionService.ProjectionStatus status, Instant staleBefore) {
        if (status == null || status.missing()) {
            return true;
        }
        if (status.driftCount() != 0L) {
            return true;
        }
        return status.lastComputedAt() == null || status.lastComputedAt().isBefore(staleBefore);
    }
}
