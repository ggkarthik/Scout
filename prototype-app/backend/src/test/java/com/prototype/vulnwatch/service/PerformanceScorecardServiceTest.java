package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.dto.PerformanceResourceCeilingItemResponse;
import com.prototype.vulnwatch.dto.SloStatusResponse;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class PerformanceScorecardServiceTest {

    @Mock
    private OperationalMetricsService operationalMetricsService;

    @Mock
    private SloMetricsService sloMetricsService;

    @Mock
    private PerformanceResourceCeilingService performanceResourceCeilingService;

    private PerformanceScorecardService service;

    @BeforeEach
    void setUp() {
        service = new PerformanceScorecardService(operationalMetricsService, sloMetricsService, performanceResourceCeilingService);
        when(operationalMetricsService.snapshot(anyString())).thenReturn(snapshot(0L, 0.0, 0.0));
        when(sloMetricsService.evaluate()).thenReturn(new SloStatusResponse(
                Instant.parse("2026-07-07T00:00:00Z"),
                true,
                List.of(
                        new SloStatusResponse.SloEntry(
                                "finding_projection_freshness",
                                "Projection freshness",
                                "tenants",
                                0L,
                                0L,
                                true,
                                "15m freshness window"
                        )
                )
        ));
        when(performanceResourceCeilingService.build()).thenReturn(List.of(
                new PerformanceResourceCeilingItemResponse(
                        "jvm-heap-utilization",
                        "JVM Heap Utilization",
                        "jvm",
                        "PASS",
                        "%",
                        75.0,
                        42.0,
                        true,
                        "Used 42% of heap."
                )
        ));
    }

    @Test
    void buildIncludesNoDataRoutesWithoutMarkingThemAsLatencyFailures() {
        when(operationalMetricsService.snapshot(OperationalMetricsService.KEY_DASHBOARD_OVERVIEW))
                .thenReturn(snapshot(0L, 0.0, 0.0));

        var response = service.build();

        assertTrue(response.overallCompliant());
        assertEquals(0, response.routeFailureCount());
        assertEquals(20, response.routeNoDataCount());
        assertEquals(0, response.freshnessFailureCount());
        assertEquals(0, response.resourceFailureCount());
        assertEquals(0, response.resourceNoDataCount());
        assertEquals("NO_DATA", response.routeItems().get(0).status());
        assertFalse(response.routeItems().get(0).compliant());
    }

    @Test
    void buildMarksObservedLatencyFailuresAgainstTargets() {
        when(operationalMetricsService.snapshot(OperationalMetricsService.KEY_DASHBOARD_OVERVIEW))
                .thenReturn(snapshot(5L, 650.0, 1100.0));
        when(operationalMetricsService.snapshot(OperationalMetricsService.KEY_FINDINGS_LIST))
                .thenReturn(snapshot(10L, 700.0, 1200.0));

        var response = service.build();

        var dashboardItem = response.routeItems().stream()
                .filter(item -> "dashboard-overview".equals(item.key()))
                .findFirst()
                .orElseThrow();
        var findingsItem = response.routeItems().stream()
                .filter(item -> "findings-list".equals(item.key()))
                .findFirst()
                .orElseThrow();

        assertEquals("FAIL", dashboardItem.status());
        assertFalse(dashboardItem.compliant());
        assertEquals("PASS", findingsItem.status());
        assertTrue(findingsItem.compliant());
        assertEquals(1, response.routeFailureCount());
        assertFalse(response.overallCompliant());
    }

    @Test
    void buildMarksResourceCeilingFailuresAsNonCompliant() {
        when(performanceResourceCeilingService.build()).thenReturn(List.of(
                new PerformanceResourceCeilingItemResponse(
                        "db-pool-active-utilization",
                        "DB Pool Active Utilization",
                        "database",
                        "FAIL",
                        "%",
                        80.0,
                        92.0,
                        false,
                        "Active connections 23 of 25."
                )
        ));

        var response = service.build();

        assertEquals("FAIL", response.resourceItems().get(0).status());
        assertFalse(response.resourceItems().get(0).compliant());
        assertEquals(1, response.resourceFailureCount());
        assertFalse(response.overallCompliant());
    }

    private OperationalMetricsService.MetricSnapshot snapshot(long requestCount, double p95Ms, double p99Ms) {
        return new OperationalMetricsService.MetricSnapshot(
                "metric",
                requestCount,
                requestCount,
                0L,
                requestCount == 0 ? 0.0 : p95Ms / 2.0,
                p95Ms,
                p99Ms,
                (long) p99Ms,
                requestCount == 0 ? 0L : (long) p95Ms,
                Instant.parse("2026-07-07T00:00:00Z")
        );
    }
}
