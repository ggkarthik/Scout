package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.FindingEvent;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.FindingQueueAnalyticsResponse;
import com.prototype.vulnwatch.dto.FindingsFilter;
import com.prototype.vulnwatch.repo.FindingEventRepository;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class FindingQueueAnalyticsServiceTest {

    @Mock private FindingListProjectionService findingListProjectionService;
    @Mock private FindingEventRepository findingEventRepository;
    @Mock private TenantSchemaExecutionService tenantSchemaExecutionService;

    private FindingQueueAnalyticsService service;
    private Tenant tenant;

    @BeforeEach
    void setUp() {
        service = new FindingQueueAnalyticsService(
                findingListProjectionService,
                findingEventRepository,
                tenantSchemaExecutionService,
                new ObjectMapper()
        );
        tenant = new Tenant();
        tenant.setId(UUID.fromString("00000000-0000-0000-0000-000000000001"));
        tenant.setName("default");
        when(tenantSchemaExecutionService.run(any(Tenant.class), org.mockito.ArgumentMatchers.<java.util.function.Supplier<Object>>any()))
                .thenAnswer(invocation -> invocation.<java.util.function.Supplier<?>>getArgument(1).get());
    }

    @Test
    void getQueueAnalyticsComputesAgingCoverageAndReopenMetrics() {
        FindingListProjectionService.ProjectionRecord openAssigned = finding(
                "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "OPEN",
                "alex@example.com",
                "INC001",
                "Platform Ops",
                5
        );
        FindingListProjectionService.ProjectionRecord openUnassigned = finding(
                "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                "OPEN",
                null,
                null,
                null,
                45
        );
        FindingListProjectionService.ProjectionRecord resolved = finding(
                "cccccccc-cccc-cccc-cccc-cccccccccccc",
                "RESOLVED",
                "alex@example.com",
                "INC002",
                "Platform Ops",
                20
        );

        when(findingListProjectionService.loadRows(any(Tenant.class), any()))
                .thenReturn(List.of(openAssigned, openUnassigned, resolved));
        when(findingEventRepository.findByFinding_IdInAndCreatedAtGreaterThanEqual(any(), any())).thenReturn(List.of(
                statusChangedEvent(openAssigned, "RESOLVED", "OPEN", Instant.now().minus(4, ChronoUnit.DAYS)),
                statusChangedEvent(resolved, "OPEN", "RESOLVED", Instant.now().minus(3, ChronoUnit.DAYS))
        ));

        FindingQueueAnalyticsResponse response = service.getQueueAnalytics(tenant, new FindingsFilter(
                null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null
        ));

        assertEquals(2, response.assignedOpenCount() + response.unassignedOpenCount());
        assertEquals(1, response.assignedOpenCount());
        assertEquals(1, response.unassignedOpenCount());
        assertEquals(1, response.withIncidentCount());
        assertEquals(1, response.withoutIncidentCount());
        assertEquals(1, response.reopenedCountLast30Days());
        assertEquals(100.0, response.reopenRatePercent());
        assertEquals(45, response.oldestOpenAgeDays());
        assertEquals(25, response.medianOpenAgeDays());
        assertEquals(List.of("0-7d", "8-30d", "31-90d", "90d+"),
                response.agingBuckets().stream().map(bucket -> bucket.key()).toList());
        assertEquals(List.of(1L, 0L, 1L, 0L),
                response.agingBuckets().stream().map(bucket -> bucket.count()).toList());
        assertEquals(List.of("Unassigned", "alex@example.com"),
                response.topOwners().stream().map(item -> item.label()).sorted().toList());
        assertEquals(List.of("No Support Group", "Platform Ops"),
                response.topSupportGroups().stream().map(item -> item.label()).sorted().toList());
    }

    @Test
    void getQueueAnalyticsTrendBuildsDailyBuckets() {
        FindingListProjectionService.ProjectionRecord finding = finding(
                "dddddddd-dddd-dddd-dddd-dddddddddddd",
                "OPEN",
                "analyst@example.com",
                null,
                "Blue Team",
                2
        );
        finding = new FindingListProjectionService.ProjectionRecord(
                finding.findingId(), finding.severity(), finding.status(), finding.decisionState(), finding.creationSource(),
                finding.matchMethod(), finding.vexStatus(), finding.vexFreshness(), finding.vexProvider(), finding.confidenceScore(),
                finding.vulnerabilityId(), finding.packageName(), finding.ecosystem(), finding.ownerGroup(), finding.assignedTo(),
                finding.incidentId(), finding.dueAt(), finding.assetName(), finding.supportGroup(), finding.patchAvailable(),
                finding.suppressedUntil(), finding.riskScore(), finding.updatedAt(), Instant.now().minus(1, ChronoUnit.DAYS), finding.firstObservedAt()
        );

        when(findingListProjectionService.loadRows(any(Tenant.class), any()))
                .thenReturn(List.of(finding));
        when(findingEventRepository.findByFinding_IdInAndCreatedAtGreaterThanEqual(any(), any())).thenReturn(List.of(
                statusChangedEvent(finding, "OPEN", "RESOLVED", Instant.now().minus(1, ChronoUnit.DAYS)),
                statusChangedEvent(finding, "RESOLVED", "OPEN", Instant.now().minus(1, ChronoUnit.DAYS))
        ));

        var trend = service.getQueueAnalyticsTrend(tenant, new FindingsFilter(
                null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null
        ), 3);

        assertEquals(3, trend.size());
        assertEquals(1L, trend.stream().mapToLong(point -> point.openedCount()).sum());
        assertEquals(1L, trend.stream().mapToLong(point -> point.resolvedCount()).sum());
        assertEquals(1L, trend.stream().mapToLong(point -> point.reopenedCount()).sum());
    }

    private FindingListProjectionService.ProjectionRecord finding(
            String id,
            String status,
            String assignedTo,
            String incidentId,
            String supportGroup,
            long ageDays
    ) {
        Instant createdAt = Instant.now().minus(ageDays, ChronoUnit.DAYS);
        return new FindingListProjectionService.ProjectionRecord(
                UUID.fromString(id),
                "CRITICAL",
                status,
                null,
                null,
                null,
                null,
                null,
                null,
                0.95,
                "CVE-2026-1234",
                "openssl",
                "rpm",
                null,
                assignedTo,
                incidentId,
                null,
                "asset-" + id.substring(0, 4),
                supportGroup,
                false,
                null,
                9.1,
                createdAt,
                createdAt,
                createdAt
        );
    }

    private FindingEvent statusChangedEvent(FindingListProjectionService.ProjectionRecord finding, String from, String to, Instant createdAt) {
        FindingEvent event = new FindingEvent();
        com.prototype.vulnwatch.domain.Finding entity = new com.prototype.vulnwatch.domain.Finding();
        org.springframework.test.util.ReflectionTestUtils.setField(entity, "id", finding.findingId());
        event.setFinding(entity);
        event.setEventType("STATUS_CHANGED");
        event.setActor("system");
        event.setSummary("Finding status changed");
        event.setDetailsJson("{\"from\":\"" + from + "\",\"to\":\"" + to + "\"}");
        org.springframework.test.util.ReflectionTestUtils.setField(event, "createdAt", createdAt);
        return event;
    }
}
