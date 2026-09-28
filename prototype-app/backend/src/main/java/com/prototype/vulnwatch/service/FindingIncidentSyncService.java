package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.ticketing.TicketingProvider;
import com.prototype.vulnwatch.ticketing.TicketingProviderRegistry;
import com.prototype.vulnwatch.ticketing.TicketingService;
import com.prototype.vulnwatch.ticketing.TicketingSystem;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Daily job that refreshes {@code findings.incident_status} from whichever ticketing system
 * raised each ticket.
 *
 * <p>Routing is per finding, not per tenant: a tenant that moved from ServiceNow to Jira still
 * has findings holding ServiceNow incident numbers, and asking Jira about {@code INC0010005}
 * would fail every time. {@link TicketingService#owningSystem(Finding)} decides where each
 * ticket is polled.
 *
 * <p>Runs once per day at 07:00.
 */
@Service
public class FindingIncidentSyncService {

    private static final Logger log = LoggerFactory.getLogger(FindingIncidentSyncService.class);

    private final FindingRepository findingRepository;
    private final TicketingProviderRegistry ticketingProviderRegistry;
    private final TicketingService ticketingService;
    private final TenantWorkRunner tenantWorkRunner;
    private BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy = BackgroundTaskExecutionPolicy.allowAll();

    public FindingIncidentSyncService(
            FindingRepository findingRepository,
            TicketingProviderRegistry ticketingProviderRegistry,
            TicketingService ticketingService,
            TenantWorkRunner tenantWorkRunner
    ) {
        this.findingRepository = findingRepository;
        this.ticketingProviderRegistry = ticketingProviderRegistry;
        this.ticketingService = ticketingService;
        this.tenantWorkRunner = tenantWorkRunner;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy) {
        this.backgroundTaskExecutionPolicy = backgroundTaskExecutionPolicy == null
                ? BackgroundTaskExecutionPolicy.allowAll()
                : backgroundTaskExecutionPolicy;
    }

    /** Scheduled daily at 07:00 to sync ticket statuses back to findings. */
    @Scheduled(cron = "0 0 7 * * *")
    public void syncIncidentStatuses() {
        if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("finding-incident-sync.sync-incident-statuses")) {
            return;
        }
        log.info("Starting ticket status sync for all linked findings");
        try {
            syncAll();
        } catch (Exception e) {
            log.error("Ticket status sync failed", e);
        }
    }

    /** Can also be invoked on-demand (e.g. from an admin endpoint). */
    public SyncResult syncAll() {
        SyncAccumulator accumulator = new SyncAccumulator();
        tenantWorkRunner.forEachActiveTenant(tenant -> accumulator.add(syncCurrentTenant()));
        SyncResult result = accumulator.toResult();
        log.info("Ticket status sync complete — updated={}, unchanged={}, failed={}",
                result.updated(), result.unchanged(), result.failed());
        return result;
    }

    private SyncResult syncCurrentTenant() {
        List<Finding> findingsWithIncident = findingRepository.findAllWithIncidentId();
        if (findingsWithIncident.isEmpty()) {
            log.info("No findings with linked tickets — nothing to sync");
            return new SyncResult(0, 0, 0);
        }

        Map<Tenant, List<Finding>> byTenant = findingsWithIncident.stream()
                .collect(Collectors.groupingBy(Finding::getTenant));

        SyncAccumulator accumulator = new SyncAccumulator();
        for (Map.Entry<Tenant, List<Finding>> tenantEntry : byTenant.entrySet()) {
            accumulator.add(syncTenantFindings(tenantEntry.getKey(), tenantEntry.getValue()));
        }
        return accumulator.toResult();
    }

    private SyncResult syncTenantFindings(Tenant tenant, List<Finding> tenantFindings) {
        // Group by the system that raised each ticket, so a tenant with both connectors polls
        // each ticket against the system that actually knows about it.
        Map<TicketingSystem, List<Finding>> bySystem = new LinkedHashMap<>();
        int unroutable = 0;
        for (Finding finding : tenantFindings) {
            Optional<TicketingSystem> system = ticketingService.owningSystem(finding);
            if (system.isEmpty()) {
                unroutable++;
                continue;
            }
            bySystem.computeIfAbsent(system.get(), ignored -> new java.util.ArrayList<>()).add(finding);
        }

        SyncAccumulator accumulator = new SyncAccumulator();
        accumulator.add(new SyncResult(0, 0, unroutable));

        for (Map.Entry<TicketingSystem, List<Finding>> entry : bySystem.entrySet()) {
            TicketingSystem system = entry.getKey();
            List<Finding> systemFindings = entry.getValue();

            Optional<TicketingProvider> providerOpt = ticketingProviderRegistry.providerFor(system);
            if (providerOpt.isEmpty()) {
                log.warn("No provider registered for ticketing system {} — skipping {} findings for tenant {}",
                        system.key(), systemFindings.size(), tenant.getId());
                accumulator.add(new SyncResult(0, 0, systemFindings.size()));
                continue;
            }
            accumulator.add(syncWithProvider(tenant, providerOpt.get(), systemFindings));
        }
        return accumulator.toResult();
    }

    private SyncResult syncWithProvider(Tenant tenant, TicketingProvider provider, List<Finding> findings) {
        int synced = 0;
        int unchanged = 0;
        int failed = 0;

        // Several findings can share one ticket; poll it once.
        Map<String, List<Finding>> byTicket = findings.stream()
                .collect(Collectors.groupingBy(Finding::getIncidentId));

        for (Map.Entry<String, List<Finding>> entry : byTicket.entrySet()) {
            String ticketKey = entry.getKey();
            List<Finding> ticketFindings = entry.getValue();

            Optional<String> newStatus;
            try {
                newStatus = provider.fetchStatus(tenant, ticketKey);
            } catch (RuntimeException ex) {
                log.warn("Failed to fetch {} status for ticket {}: {}",
                        provider.system().key(), ticketKey, ex.getMessage());
                newStatus = Optional.empty();
            }

            if (newStatus.isEmpty()) {
                // Leave the last known status in place — a transient outage must not look like
                // a status change.
                log.warn("Could not fetch {} status for ticket {} — skipping", provider.system().key(), ticketKey);
                failed += ticketFindings.size();
                continue;
            }

            String status = newStatus.get();
            for (Finding finding : ticketFindings) {
                if (!status.equals(finding.getIncidentStatus())) {
                    finding.setIncidentStatus(status);
                    finding.touch();
                    synced++;
                } else {
                    unchanged++;
                }
            }
            findingRepository.saveAll(ticketFindings);
        }

        return new SyncResult(synced, unchanged, failed);
    }

    public record SyncResult(int updated, int unchanged, int failed) {}

    private static final class SyncAccumulator {
        private int updated;
        private int unchanged;
        private int failed;

        void add(SyncResult result) {
            updated += result.updated();
            unchanged += result.unchanged();
            failed += result.failed();
        }

        SyncResult toResult() {
            return new SyncResult(updated, unchanged, failed);
        }
    }
}
