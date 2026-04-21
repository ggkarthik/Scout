package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.FindingRepository;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Daily job that polls ServiceNow for the current status of every incident
 * that was linked to a finding, and writes the result back to {@code findings.incident_status}.
 *
 * <p>Runs once per day at 07:00 (configurable via the cron expression).
 */
@Service
public class FindingIncidentSyncService {

    private static final Logger log = LoggerFactory.getLogger(FindingIncidentSyncService.class);

    private final FindingRepository findingRepository;
    private final ServiceNowIncidentService serviceNowIncidentService;
    private final ServiceNowCmdbConfigService serviceNowCmdbConfigService;
    private final TenantService tenantService;

    public FindingIncidentSyncService(
            FindingRepository findingRepository,
            ServiceNowIncidentService serviceNowIncidentService,
            ServiceNowCmdbConfigService serviceNowCmdbConfigService,
            TenantService tenantService
    ) {
        this.findingRepository = findingRepository;
        this.serviceNowIncidentService = serviceNowIncidentService;
        this.serviceNowCmdbConfigService = serviceNowCmdbConfigService;
        this.tenantService = tenantService;
    }

    /** Scheduled daily at 07:00 to sync ServiceNow incident statuses back to findings. */
    @Scheduled(cron = "0 0 7 * * *")
    public void syncIncidentStatuses() {
        log.info("Starting ServiceNow incident status sync for all linked findings");
        try {
            syncAll();
        } catch (Exception e) {
            log.error("ServiceNow incident status sync failed", e);
        }
    }

    /** Can also be invoked on-demand (e.g. from an admin endpoint). */
    @Transactional
    public SyncResult syncAll() {
        List<Finding> findingsWithIncident = findingRepository.findAllWithIncidentId();
        if (findingsWithIncident.isEmpty()) {
            log.info("No findings with linked ServiceNow incidents — nothing to sync");
            return new SyncResult(0, 0, 0);
        }

        // Group by tenant to resolve one config per tenant
        Map<Tenant, List<Finding>> byTenant = findingsWithIncident.stream()
                .collect(Collectors.groupingBy(Finding::getTenant));

        int synced = 0;
        int unchanged = 0;
        int failed = 0;

        for (Map.Entry<Tenant, List<Finding>> entry : byTenant.entrySet()) {
            Tenant tenant = entry.getKey();
            List<Finding> tenantFindings = entry.getValue();

            var configOpt = serviceNowCmdbConfigService.resolveRuntimeConfig(tenant);
            if (configOpt.isEmpty()) {
                log.warn("ServiceNow not configured for tenant {} — skipping {} findings",
                        tenant.getId(), tenantFindings.size());
                failed += tenantFindings.size();
                continue;
            }
            var config = configOpt.get();

            // Group by incident ID to avoid redundant API calls for the same incident
            Map<String, List<Finding>> byIncident = tenantFindings.stream()
                    .collect(Collectors.groupingBy(Finding::getIncidentId));

            for (Map.Entry<String, List<Finding>> incEntry : byIncident.entrySet()) {
                String incidentNumber = incEntry.getKey();
                String newStatus = serviceNowIncidentService.getIncidentStatus(config, incidentNumber);

                if (newStatus == null) {
                    log.warn("Could not fetch status for incident {} — skipping", incidentNumber);
                    failed += incEntry.getValue().size();
                    continue;
                }

                for (Finding f : incEntry.getValue()) {
                    if (!newStatus.equals(f.getIncidentStatus())) {
                        f.setIncidentStatus(newStatus);
                        f.touch();
                        synced++;
                    } else {
                        unchanged++;
                    }
                }
                findingRepository.saveAll(incEntry.getValue());
            }
        }

        log.info("ServiceNow incident status sync complete — updated={}, unchanged={}, failed={}",
                synced, unchanged, failed);
        return new SyncResult(synced, unchanged, failed);
    }

    public record SyncResult(int updated, int unchanged, int failed) {}
}
