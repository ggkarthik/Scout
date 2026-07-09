package com.prototype.vulnwatch.config;

import com.prototype.vulnwatch.service.OperationalMetricsService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

@Component
public class OperationalMetricsInterceptor implements HandlerInterceptor {

    private static final String START_TIME_ATTRIBUTE = "operationalMetricsStartTimeNs";
    private final OperationalMetricsService operationalMetricsService;

    public OperationalMetricsInterceptor(OperationalMetricsService operationalMetricsService) {
        this.operationalMetricsService = operationalMetricsService;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        request.setAttribute(START_TIME_ATTRIBUTE, System.nanoTime());
        return true;
    }

    @Override
    public void afterCompletion(
            HttpServletRequest request,
            HttpServletResponse response,
            Object handler,
            Exception ex
    ) {
        Object startTimeValue = request.getAttribute(START_TIME_ATTRIBUTE);
        if (!(startTimeValue instanceof Long startTimeNs)) {
            return;
        }
        String metricKey = metricKeyForRequest(request);
        if (metricKey == null) {
            return;
        }
        long durationMs = (System.nanoTime() - startTimeNs) / 1_000_000L;
        operationalMetricsService.record(metricKey, durationMs, response.getStatus());
    }

    private String metricKeyForRequest(HttpServletRequest request) {
        String method = request.getMethod();
        String path = request.getRequestURI();
        if ("GET".equalsIgnoreCase(method) && "/api/vulnerability-intelligence".equals(path)) {
            return OperationalMetricsService.KEY_VULN_INTEL_LIST;
        }
        if ("GET".equalsIgnoreCase(method) && "/api/vulnerability-intelligence/filters".equals(path)) {
            return OperationalMetricsService.KEY_VULN_INTEL_FILTERS;
        }
        if ("GET".equalsIgnoreCase(method) && "/api/vuln-repo/dashboard".equals(path)) {
            return OperationalMetricsService.KEY_VULN_REPO_DASHBOARD;
        }
        if ("GET".equalsIgnoreCase(method) && "/api/vuln-repo/vulnerabilities".equals(path)) {
            return OperationalMetricsService.KEY_VULN_REPO_VULNERABILITIES;
        }
        if ("GET".equalsIgnoreCase(method) && "/api/vuln-repo/org-cves".equals(path)) {
            return OperationalMetricsService.KEY_VULN_REPO_ORG_CVES;
        }
        if ("GET".equalsIgnoreCase(method) && "/api/vuln-repo/org-cves/status".equals(path)) {
            return OperationalMetricsService.KEY_VULN_REPO_ORG_CVE_STATUS;
        }
        if ("POST".equalsIgnoreCase(method) && "/api/vuln-repo/org-cves/recompute".equals(path)) {
            return OperationalMetricsService.KEY_VULN_REPO_ORG_CVE_RECOMPUTE;
        }
        if ("GET".equalsIgnoreCase(method) && "/api/dashboard".equals(path)) {
            return OperationalMetricsService.KEY_DASHBOARD_OVERVIEW;
        }
        if ("GET".equalsIgnoreCase(method) && "/api/dashboard/applicable-software".equals(path)) {
            return OperationalMetricsService.KEY_DASHBOARD_APPLICABLE_SOFTWARE;
        }
        if ("GET".equalsIgnoreCase(method) && "/api/dashboard/impacted-cves".equals(path)) {
            return OperationalMetricsService.KEY_DASHBOARD_IMPACTED_CVES;
        }
        if ("GET".equalsIgnoreCase(method) && "/api/dashboard/cve-inventory-map".equals(path)) {
            return OperationalMetricsService.KEY_DASHBOARD_CVE_INVENTORY_MAP;
        }
        if ("GET".equalsIgnoreCase(method) && "/api/operations/dashboard".equals(path)) {
            return OperationalMetricsService.KEY_OPERATIONS_DASHBOARD;
        }
        if ("GET".equalsIgnoreCase(method) && "/api/operations/overview".equals(path)) {
            return OperationalMetricsService.KEY_OPERATIONS_OVERVIEW;
        }
        if ("GET".equalsIgnoreCase(method) && "/api/operations/ingestion-efficiency".equals(path)) {
            return OperationalMetricsService.KEY_OPERATIONS_INGESTION;
        }
        if ("GET".equalsIgnoreCase(method) && "/api/operations/normalization-quality".equals(path)) {
            return OperationalMetricsService.KEY_OPERATIONS_NORMALIZATION;
        }
        if ("GET".equalsIgnoreCase(method) && "/api/operations/correlation-effectiveness".equals(path)) {
            return OperationalMetricsService.KEY_OPERATIONS_CORRELATION;
        }
        if ("GET".equalsIgnoreCase(method) && "/api/operations/noise-lifecycle".equals(path)) {
            return OperationalMetricsService.KEY_OPERATIONS_LIFECYCLE;
        }
        if ("GET".equalsIgnoreCase(method) && "/api/operations/api-read-path".equals(path)) {
            return OperationalMetricsService.KEY_OPERATIONS_READ_PATH;
        }
        if ("GET".equalsIgnoreCase(method) && "/api/operations/freshness-drift".equals(path)) {
            return OperationalMetricsService.KEY_OPERATIONS_FRESHNESS;
        }
        if ("GET".equalsIgnoreCase(method) && "/api/operations/metric-catalog".equals(path)) {
            return OperationalMetricsService.KEY_OPERATIONS_CATALOG;
        }
        if ("GET".equalsIgnoreCase(method) && "/api/findings".equals(path)) {
            return OperationalMetricsService.KEY_FINDINGS_LIST;
        }
        if ("GET".equalsIgnoreCase(method) && "/api/findings/summary".equals(path)) {
            return OperationalMetricsService.KEY_FINDINGS_SUMMARY;
        }
        if ("GET".equalsIgnoreCase(method) && "/api/findings/distributions".equals(path)) {
            return OperationalMetricsService.KEY_FINDINGS_DISTRIBUTIONS;
        }
        if ("GET".equalsIgnoreCase(method) && "/api/findings/backlog-health".equals(path)) {
            return OperationalMetricsService.KEY_FINDINGS_BACKLOG_HEALTH;
        }
        if ("GET".equalsIgnoreCase(method) && "/api/findings/filters".equals(path)) {
            return OperationalMetricsService.KEY_FINDINGS_FILTERS;
        }
        if ("GET".equalsIgnoreCase(method) && "/api/findings/projection-status".equals(path)) {
            return OperationalMetricsService.KEY_FINDINGS_PROJECTION_STATUS;
        }
        if ("GET".equalsIgnoreCase(method) && "/api/inventory/components".equals(path)) {
            return OperationalMetricsService.KEY_INVENTORY_COMPONENTS;
        }
        if ("GET".equalsIgnoreCase(method) && "/api/inventory/components/filters".equals(path)) {
            return OperationalMetricsService.KEY_INVENTORY_COMPONENT_FILTERS;
        }
        if ("GET".equalsIgnoreCase(method) && "/api/inventory/software-identities".equals(path)) {
            return OperationalMetricsService.KEY_INVENTORY_SOFTWARE_IDENTITIES;
        }
        if ("GET".equalsIgnoreCase(method) && "/api/inventory/software-identities/funnel".equals(path)) {
            return OperationalMetricsService.KEY_INVENTORY_SOFTWARE_IDENTITY_FUNNEL;
        }
        if ("POST".equalsIgnoreCase(method) && "/api/sbom-fetch".equals(path)) {
            return OperationalMetricsService.KEY_SBOM_FETCH_ENDPOINT;
        }
        if ("POST".equalsIgnoreCase(method) && "/api/github-sbom-sources/repository/run".equals(path)) {
            return OperationalMetricsService.KEY_SBOM_FETCH_GITHUB;
        }
        if ("POST".equalsIgnoreCase(method) && "/api/github-sbom-sources/ghcr/run".equals(path)) {
            return OperationalMetricsService.KEY_SBOM_FETCH_GITHUB;
        }
        if ("POST".equalsIgnoreCase(method)
                && path.startsWith("/api/github-sbom-sources/")
                && path.endsWith("/run")) {
            return OperationalMetricsService.KEY_SBOM_FETCH_GITHUB;
        }
        if ("POST".equalsIgnoreCase(method) && "/api/ingestion/nvd-sync".equals(path)) {
            return OperationalMetricsService.KEY_INGESTION_NVD_SYNC;
        }
        if ("POST".equalsIgnoreCase(method) && "/api/ingestion/nvd-full-sync".equals(path)) {
            return OperationalMetricsService.KEY_INGESTION_NVD_FULL_SYNC;
        }
        if ("POST".equalsIgnoreCase(method) && "/api/ingestion/kev-sync".equals(path)) {
            return OperationalMetricsService.KEY_INGESTION_KEV_SYNC;
        }
        if ("POST".equalsIgnoreCase(method) && "/api/ingestion/ghsa-sync".equals(path)) {
            return OperationalMetricsService.KEY_INGESTION_GHSA_SYNC;
        }
        if ("POST".equalsIgnoreCase(method) && "/api/ingestion/csaf/microsoft-sync".equals(path)) {
            return OperationalMetricsService.KEY_INGESTION_CSAF_MICROSOFT_SYNC;
        }
        if ("POST".equalsIgnoreCase(method) && "/api/ingestion/csaf/redhat-sync".equals(path)) {
            return OperationalMetricsService.KEY_INGESTION_CSAF_REDHAT_SYNC;
        }
        if ("POST".equalsIgnoreCase(method) && "/api/ingestion/advisories".equals(path)) {
            return OperationalMetricsService.KEY_INGESTION_ADVISORIES;
        }
        if ("POST".equalsIgnoreCase(method) && "/api/ingestion/recompute-findings".equals(path)) {
            return OperationalMetricsService.KEY_INGESTION_RECOMPUTE_FINDINGS;
        }
        return null;
    }
}
