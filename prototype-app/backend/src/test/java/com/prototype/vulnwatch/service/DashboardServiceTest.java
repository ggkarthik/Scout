package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.dto.DashboardNoiseReductionResponse;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.ComponentVulnerabilityStateRepository;
import com.prototype.vulnwatch.repo.FindingEventRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.InventoryComponentCpeMapRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.SyncRunRepository;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class DashboardServiceTest {

    @Mock
    private AssetRepository assetRepository;

    @Mock
    private InventoryComponentRepository inventoryComponentRepository;

    @Mock
    private InventoryComponentCpeMapRepository inventoryComponentCpeMapRepository;

    @Mock
    private ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository;

    @Mock
    private FindingRepository findingRepository;

    @Mock
    private FindingEventRepository findingEventRepository;

    @Mock
    private FindingService findingService;

    @Mock
    private DashboardNoiseReductionProjectionService dashboardNoiseReductionProjectionService;

    @Mock
    private SyncRunRepository syncRunRepository;

    @Test
    void buildNoiseReductionUsesProjectionInsteadOfLiveCorrelationRead() {
        DashboardService service = new DashboardService(
                assetRepository,
                inventoryComponentRepository,
                inventoryComponentCpeMapRepository,
                componentVulnerabilityStateRepository,
                findingRepository,
                findingEventRepository,
                findingService,
                dashboardNoiseReductionProjectionService,
                syncRunRepository,
                new ObjectMapper()
        );
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());

        when(dashboardNoiseReductionProjectionService.getTenantProjection(tenant))
                .thenReturn(new DashboardNoiseReductionProjectionService.ProjectionSnapshot(
                        12L,
                        4L,
                        Map.of(
                                "VEX Not Affected", 9L,
                                "Correlation Not Affected", 3L
                        ),
                        Instant.parse("2026-03-22T08:00:00Z")
                ));
        when(findingRepository.countByTenantAndStatusAndDecisionStateWithEvent(
                tenant,
                FindingStatus.RESOLVED,
                FindingDecisionState.NOT_AFFECTED,
                "AUTO_RESOLVED_NOT_OBSERVED"
        )).thenReturn(5L);
        when(findingEventRepository.findByTenantAndEventTypeSince(
                eq(tenant),
                eq("AUTO_RESOLVED_NOT_OBSERVED"),
                any(Instant.class)
        )).thenReturn(List.of());

        DashboardNoiseReductionResponse response = ReflectionTestUtils.invokeMethod(
                service,
                "buildNoiseReduction",
                tenant,
                20L
        );

        assertEquals(17L, response.totalFilteredNotApplicable());
        assertEquals(12L, response.neverOpenedNotApplicable());
        assertEquals(5L, response.autoResolvedNotApplicable());
        assertEquals(4L, response.deferredUnderInvestigation());
        assertEquals(37L, response.potentialFindingsWithoutCorrelation());
        assertTrue(response.categories().stream().anyMatch(metric ->
                "VEX Not Affected".equals(metric.key()) && metric.count() == 9L));
        assertTrue(response.categories().stream().anyMatch(metric ->
                "Auto-Resolved (No Longer Observed)".equals(metric.key()) && metric.count() == 5L));

        verify(dashboardNoiseReductionProjectionService).getTenantProjection(tenant);
        verify(findingService, never()).projectNotApplicableByCorrelation(any(Tenant.class));
    }
}
