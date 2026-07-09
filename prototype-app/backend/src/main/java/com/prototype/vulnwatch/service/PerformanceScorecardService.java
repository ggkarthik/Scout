package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.dto.PerformanceRouteScorecardItemResponse;
import com.prototype.vulnwatch.dto.PerformanceResourceCeilingItemResponse;
import com.prototype.vulnwatch.dto.PerformanceScorecardResponse;
import com.prototype.vulnwatch.dto.PerformanceSloScorecardItemResponse;
import com.prototype.vulnwatch.dto.SloStatusResponse;
import java.time.Instant;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class PerformanceScorecardService {

    private static final String SCALE_PROFILE = "1M inventory components / 250k findings / 100 concurrent users";

    private final OperationalMetricsService operationalMetricsService;
    private final SloMetricsService sloMetricsService;
    private final PerformanceResourceCeilingService performanceResourceCeilingService;

    public PerformanceScorecardService(
            OperationalMetricsService operationalMetricsService,
            SloMetricsService sloMetricsService,
            PerformanceResourceCeilingService performanceResourceCeilingService
    ) {
        this.operationalMetricsService = operationalMetricsService;
        this.sloMetricsService = sloMetricsService;
        this.performanceResourceCeilingService = performanceResourceCeilingService;
    }

    public PerformanceScorecardResponse build() {
        Instant now = Instant.now();
        List<PerformanceRouteScorecardItemResponse> routeItems = List.of(
                route("dashboard-overview", "Exposure Dashboard", "/api/dashboard", "dashboard-summary",
                        OperationalMetricsService.KEY_DASHBOARD_OVERVIEW, 500.0, 1000.0),
                route("dashboard-applicable-software", "Applicable Software", "/api/dashboard/applicable-software", "paginated-list",
                        OperationalMetricsService.KEY_DASHBOARD_APPLICABLE_SOFTWARE, 800.0, 1500.0),
                route("dashboard-impacted-cves", "Impacted CVEs", "/api/dashboard/impacted-cves", "paginated-list",
                        OperationalMetricsService.KEY_DASHBOARD_IMPACTED_CVES, 800.0, 1500.0),
                route("dashboard-cve-inventory-map", "CVE Inventory Map", "/api/dashboard/cve-inventory-map", "dashboard-summary",
                        OperationalMetricsService.KEY_DASHBOARD_CVE_INVENTORY_MAP, 500.0, 1000.0),
                route("findings-list", "Findings List", "/api/findings", "paginated-list",
                        OperationalMetricsService.KEY_FINDINGS_LIST, 800.0, 1500.0),
                route("findings-summary", "Findings Summary", "/api/findings/summary", "dashboard-summary",
                        OperationalMetricsService.KEY_FINDINGS_SUMMARY, 500.0, 1000.0),
                route("findings-distributions", "Findings Distributions", "/api/findings/distributions", "dashboard-summary",
                        OperationalMetricsService.KEY_FINDINGS_DISTRIBUTIONS, 500.0, 1000.0),
                route("findings-backlog-health", "Findings Backlog Health", "/api/findings/backlog-health", "dashboard-summary",
                        OperationalMetricsService.KEY_FINDINGS_BACKLOG_HEALTH, 500.0, 1000.0),
                route("findings-filters", "Findings Filters", "/api/findings/filters", "filter-metadata",
                        OperationalMetricsService.KEY_FINDINGS_FILTERS, 250.0, 500.0),
                route("findings-projection-status", "Findings Projection Status", "/api/findings/projection-status", "filter-metadata",
                        OperationalMetricsService.KEY_FINDINGS_PROJECTION_STATUS, 250.0, 500.0),
                route("inventory-components", "Inventory Components", "/api/inventory/components", "paginated-list",
                        OperationalMetricsService.KEY_INVENTORY_COMPONENTS, 800.0, 1500.0),
                route("inventory-component-filters", "Inventory Component Filters", "/api/inventory/components/filters", "filter-metadata",
                        OperationalMetricsService.KEY_INVENTORY_COMPONENT_FILTERS, 250.0, 500.0),
                route("software-identities", "Software Identities", "/api/inventory/software-identities", "paginated-list",
                        OperationalMetricsService.KEY_INVENTORY_SOFTWARE_IDENTITIES, 800.0, 1500.0),
                route("software-identity-funnel", "Software Identity Funnel", "/api/inventory/software-identities/funnel", "dashboard-summary",
                        OperationalMetricsService.KEY_INVENTORY_SOFTWARE_IDENTITY_FUNNEL, 500.0, 1000.0),
                route("vulnerability-intelligence-list", "Vulnerability Intelligence List", "/api/vulnerability-intelligence", "paginated-list",
                        OperationalMetricsService.KEY_VULN_INTEL_LIST, 800.0, 1500.0),
                route("vulnerability-intelligence-filters", "Vulnerability Intelligence Filters", "/api/vulnerability-intelligence/filters", "filter-metadata",
                        OperationalMetricsService.KEY_VULN_INTEL_FILTERS, 250.0, 500.0),
                route("vuln-repo-dashboard", "Vulnerability Repository Dashboard", "/api/vuln-repo/dashboard", "dashboard-summary",
                        OperationalMetricsService.KEY_VULN_REPO_DASHBOARD, 500.0, 1000.0),
                route("vuln-repo-vulnerabilities", "Vulnerability Repository Vulnerabilities", "/api/vuln-repo/vulnerabilities", "paginated-list",
                        OperationalMetricsService.KEY_VULN_REPO_VULNERABILITIES, 800.0, 1500.0),
                route("vuln-repo-org-cves", "Vulnerability Investigation", "/api/vuln-repo/org-cves", "paginated-list",
                        OperationalMetricsService.KEY_VULN_REPO_ORG_CVES, 800.0, 1500.0),
                route("vuln-repo-org-cves-status", "Vulnerability Investigation Status", "/api/vuln-repo/org-cves/status", "dashboard-summary",
                        OperationalMetricsService.KEY_VULN_REPO_ORG_CVE_STATUS, 500.0, 1000.0)
        );

        SloStatusResponse sloStatus = sloMetricsService.evaluate();
        List<PerformanceSloScorecardItemResponse> freshnessItems = sloStatus.slos().stream()
                .map(entry -> new PerformanceSloScorecardItemResponse(
                        entry.name(),
                        entry.description(),
                        entry.unit(),
                        entry.target(),
                        entry.current(),
                        entry.compliant(),
                        entry.window()
                ))
                .toList();
        List<PerformanceResourceCeilingItemResponse> resourceItems = performanceResourceCeilingService.build();
        long routeFailureCount = routeItems.stream().filter(item -> "FAIL".equals(item.status())).count();
        long routeNoDataCount = routeItems.stream().filter(item -> "NO_DATA".equals(item.status())).count();
        long freshnessFailureCount = freshnessItems.stream().filter(item -> !item.compliant()).count();
        long resourceFailureCount = resourceItems.stream().filter(item -> "FAIL".equals(item.status())).count();
        long resourceNoDataCount = resourceItems.stream().filter(item -> "NO_DATA".equals(item.status())).count();

        boolean routeCompliance = routeItems.stream().allMatch(item ->
                "PASS".equals(item.status()) || "NO_DATA".equals(item.status()));
        boolean freshnessCompliance = freshnessItems.stream().allMatch(PerformanceSloScorecardItemResponse::compliant);
        boolean resourceCompliance = resourceItems.stream().allMatch(item ->
                "PASS".equals(item.status()) || "NO_DATA".equals(item.status()));

        return new PerformanceScorecardResponse(
                now,
                SCALE_PROFILE,
                routeCompliance && freshnessCompliance && resourceCompliance,
                routeFailureCount,
                routeNoDataCount,
                freshnessFailureCount,
                resourceFailureCount,
                resourceNoDataCount,
                routeItems,
                freshnessItems,
                resourceItems
        );
    }

    private PerformanceRouteScorecardItemResponse route(
            String key,
            String label,
            String path,
            String category,
            String metricKey,
            double targetP95Ms,
            double targetP99Ms
    ) {
        OperationalMetricsService.MetricSnapshot snapshot = operationalMetricsService.snapshot(metricKey);
        if (snapshot.requestCount() <= 0) {
            return new PerformanceRouteScorecardItemResponse(
                    key,
                    label,
                    path,
                    category,
                    "NO_DATA",
                    "ms",
                    targetP95Ms,
                    targetP99Ms,
                    0L,
                    0.0,
                    0.0,
                    false,
                    "No samples recorded yet for this route in the current runtime window."
            );
        }
        boolean compliant = snapshot.p95Ms() <= targetP95Ms && snapshot.p99Ms() <= targetP99Ms;
        return new PerformanceRouteScorecardItemResponse(
                key,
                label,
                path,
                category,
                compliant ? "PASS" : "FAIL",
                "ms",
                targetP95Ms,
                targetP99Ms,
                snapshot.requestCount(),
                snapshot.p95Ms(),
                snapshot.p99Ms(),
                compliant,
                compliant ? "Observed latency is within the current target envelope."
                        : "Observed latency exceeds at least one current target."
        );
    }
}
