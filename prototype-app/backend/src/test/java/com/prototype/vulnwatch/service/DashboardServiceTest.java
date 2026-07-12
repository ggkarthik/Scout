package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.dto.DashboardNoiseReductionResponse;
import com.prototype.vulnwatch.dto.GridExposureResponse;
import com.prototype.vulnwatch.dto.GridExposureRowResponse;
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
    private FindingQueryService findingQueryService;

    @Mock
    private DashboardNoiseReductionProjectionService dashboardNoiseReductionProjectionService;

    @Mock
    private SyncRunRepository syncRunRepository;
    @Mock
    private TenantSchemaExecutionService tenantSchemaExecutionService;

    @Test
    void buildNoiseReductionUsesProjectionInsteadOfLiveCorrelationRead() {
        DashboardService service = new DashboardService(
                assetRepository,
                inventoryComponentRepository,
                inventoryComponentCpeMapRepository,
                componentVulnerabilityStateRepository,
                findingRepository,
                findingEventRepository,
                findingQueryService,
                dashboardNoiseReductionProjectionService,
                syncRunRepository,
                new ObjectMapper(),
                tenantSchemaExecutionService
        );
        doAnswer(invocation -> invocation.getArgument(1, java.util.function.Supplier.class).get())
                .when(tenantSchemaExecutionService)
                .run(org.mockito.ArgumentMatchers.nullable(Tenant.class), org.mockito.ArgumentMatchers.<java.util.function.Supplier<Object>>any());
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
        when(findingRepository.countByStatusAndDecisionStateWithEvent(
                FindingStatus.RESOLVED,
                FindingDecisionState.NOT_AFFECTED,
                "AUTO_RESOLVED_NOT_OBSERVED"
        )).thenReturn(5L);
        when(findingEventRepository.findByEventTypeAndCreatedAtGreaterThanEqual(
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
        verifyNoInteractions(findingQueryService);
    }

    @Test
    void getGridExposureGroupsOpenFindingsByAssetTypeAndSeverityAndSeedsAllAssetTypes() {
        DashboardService service = new DashboardService(
                assetRepository,
                inventoryComponentRepository,
                inventoryComponentCpeMapRepository,
                componentVulnerabilityStateRepository,
                findingRepository,
                findingEventRepository,
                findingQueryService,
                dashboardNoiseReductionProjectionService,
                syncRunRepository,
                new ObjectMapper(),
                tenantSchemaExecutionService
        );
        doAnswer(invocation -> invocation.getArgument(1, java.util.function.Supplier.class).get())
                .when(tenantSchemaExecutionService)
                .run(org.mockito.ArgumentMatchers.nullable(Tenant.class), org.mockito.ArgumentMatchers.<java.util.function.Supplier<Object>>any());
        Tenant tenant = new Tenant();
        UUID tenantId = UUID.randomUUID();
        tenant.setId(tenantId);

        when(findingRepository.countOpenByAssetTypeAndSeverityForTenant(tenantId)).thenReturn(List.of(
                new Object[]{"HOST", "CRITICAL", 3L},
                new Object[]{"HOST", "HIGH", 2L},
                new Object[]{"APPLICATION", "medium", 5L},
                new Object[]{null, "LOW", 1L}
        ));

        GridExposureResponse response = service.getGridExposure(tenant);

        assertEquals(AssetType.values().length, response.rows().size());
        GridExposureRowResponse hostRow = response.rows().stream()
                .filter(row -> "HOST".equals(row.assetType()))
                .findFirst()
                .orElseThrow();
        assertEquals(3L, hostRow.critical());
        assertEquals(2L, hostRow.high());
        assertEquals(0L, hostRow.medium());
        assertEquals(5L, hostRow.total());

        GridExposureRowResponse applicationRow = response.rows().stream()
                .filter(row -> "APPLICATION".equals(row.assetType()))
                .findFirst()
                .orElseThrow();
        assertEquals(5L, applicationRow.medium());
        assertEquals(5L, applicationRow.total());

        GridExposureRowResponse containerRow = response.rows().stream()
                .filter(row -> "CONTAINER_IMAGE".equals(row.assetType()))
                .findFirst()
                .orElseThrow();
        assertEquals(0L, containerRow.total());
    }
}
