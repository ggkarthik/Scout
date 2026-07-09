package com.prototype.vulnwatch.config;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.longThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import com.prototype.vulnwatch.service.OperationalMetricsService;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class OperationalMetricsInterceptorTest {

    private final OperationalMetricsService operationalMetricsService = mock(OperationalMetricsService.class);
    private final OperationalMetricsInterceptor interceptor = new OperationalMetricsInterceptor(operationalMetricsService);

    @ParameterizedTest
    @CsvSource({
            "GET,/api/dashboard/applicable-software,dashboard-applicable-software",
            "GET,/api/dashboard/impacted-cves,dashboard-impacted-cves",
            "GET,/api/dashboard/cve-inventory-map,dashboard-cve-inventory-map",
            "GET,/api/vuln-repo/dashboard,vuln-repo-dashboard",
            "GET,/api/vuln-repo/vulnerabilities,vuln-repo-vulnerabilities",
            "GET,/api/vuln-repo/org-cves,vuln-repo-org-cves",
            "GET,/api/vuln-repo/org-cves/status,vuln-repo-org-cves-status",
            "POST,/api/vuln-repo/org-cves/recompute,vuln-repo-org-cves-recompute",
            "GET,/api/findings/summary,findings-summary",
            "GET,/api/findings/distributions,findings-distributions",
            "GET,/api/findings/backlog-health,findings-backlog-health",
            "GET,/api/findings/filters,findings-filters",
            "GET,/api/findings/projection-status,findings-projection-status",
            "GET,/api/inventory/components,inventory-components",
            "GET,/api/inventory/components/filters,inventory-component-filters",
            "GET,/api/inventory/software-identities,inventory-software-identities",
            "GET,/api/inventory/software-identities/funnel,inventory-software-identity-funnel"
    })
    void recordsRepoEndpointsUnderRepoMetricKeys(String method, String path, String expectedKey) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest(method, path);
        MockHttpServletResponse response = new MockHttpServletResponse();

        interceptor.preHandle(request, response, new Object());
        response.setStatus(200);
        interceptor.afterCompletion(request, response, new Object(), null);

        verify(operationalMetricsService).record(eq(expectedKey), longThat(value -> value >= 0L), eq(200));
    }
}
