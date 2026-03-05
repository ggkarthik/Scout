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
        if ("GET".equalsIgnoreCase(method) && "/api/dashboard".equals(path)) {
            return OperationalMetricsService.KEY_DASHBOARD_OVERVIEW;
        }
        if ("GET".equalsIgnoreCase(method) && "/api/operations/dashboard".equals(path)) {
            return OperationalMetricsService.KEY_OPERATIONS_DASHBOARD;
        }
        if ("GET".equalsIgnoreCase(method) && "/api/findings".equals(path)) {
            return OperationalMetricsService.KEY_FINDINGS_LIST;
        }
        if ("POST".equalsIgnoreCase(method) && "/api/sbom-upload".equals(path)) {
            return OperationalMetricsService.KEY_SBOM_UPLOAD;
        }
        if ("POST".equalsIgnoreCase(method) && "/api/sbom-fetch".equals(path)) {
            return OperationalMetricsService.KEY_SBOM_FETCH_ENDPOINT;
        }
        if ("POST".equalsIgnoreCase(method) && "/api/sbom-fetch/github".equals(path)) {
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
