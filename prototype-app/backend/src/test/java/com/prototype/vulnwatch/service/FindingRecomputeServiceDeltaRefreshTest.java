package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.VulnerabilityTargetType;
import com.prototype.vulnwatch.repo.ComponentVulnerabilityStateRepository;
import com.prototype.vulnwatch.repo.InventoryComponentCpeMapRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.OrgCveRecordRepository;
import com.prototype.vulnwatch.repo.VulnerabilityTargetRepository;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class FindingRecomputeServiceDeltaRefreshTest {

    @Mock
    private FindingAssetRecomputeService findingAssetRecomputeService;

    @Mock
    private FindingComponentRecomputeService findingComponentRecomputeService;

    @Mock
    private ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository;

    @Mock
    private FindingCorrelationProjectionService findingCorrelationProjectionService;

    @Mock
    private InventoryComponentRepository inventoryComponentRepository;

    @Mock
    private InventoryComponentCpeMapRepository inventoryComponentCpeMapRepository;

    @Mock
    private VulnerabilityTargetRepository vulnerabilityTargetRepository;

    @Mock
    private OrgCveRecordRepository orgCveRecordRepository;

    @Mock
    private OrgCveRecordService orgCveRecordService;

    @Mock
    private TenantWorkRunner tenantWorkRunner;

    private FindingRecomputeService findingRecomputeService;

    @BeforeEach
    void setUp() {
        findingRecomputeService = new FindingRecomputeService(
                findingAssetRecomputeService,
                findingComponentRecomputeService,
                findingCorrelationProjectionService,
                componentVulnerabilityStateRepository,
                inventoryComponentRepository,
                inventoryComponentCpeMapRepository,
                vulnerabilityTargetRepository,
                orgCveRecordRepository,
                orgCveRecordService,
                tenantWorkRunner
        );
        org.mockito.Mockito.lenient().when(tenantWorkRunner.runScoped(org.mockito.ArgumentMatchers.any(UUID.class), org.mockito.ArgumentMatchers.any(Supplier.class)))
                .thenAnswer(invocation -> invocation.getArgument(1, Supplier.class).get());
    }

    @Test
    void recomputeForAssetDelegatesToAssetService() {
        Tenant tenant = new Tenant();
        Asset asset = new Asset();
        when(findingAssetRecomputeService.recomputeForAsset(tenant, asset)).thenReturn(5);

        int total = findingRecomputeService.recomputeForAsset(tenant, asset);

        assertEquals(5, total);
        verify(findingAssetRecomputeService).recomputeForAsset(tenant, asset);
    }

    @Test
    void recomputeForAssetsDelegatesToAssetService() {
        Asset asset = new Asset();
        List<Asset> assets = List.of(asset);
        when(findingAssetRecomputeService.recomputeForAssets(assets)).thenReturn(2);

        int total = findingRecomputeService.recomputeForAssets(assets);

        assertEquals(2, total);
        verify(findingAssetRecomputeService).recomputeForAssets(assets);
    }

    @Test
    void recomputeOnCveDeltaBatchRefreshesMetadataOnlyForTenantsWithoutComponentRecompute() {
        UUID vulnerabilityId = UUID.randomUUID();
        UUID recomputedTenantId = UUID.randomUUID();
        UUID metadataOnlyTenantId = UUID.randomUUID();
        UUID componentId = UUID.randomUUID();
        List<UUID> vulnerabilityIds = List.of(vulnerabilityId);

        stubDeltaScope(vulnerabilityIds, recomputedTenantId, metadataOnlyTenantId, componentId);
        when(findingComponentRecomputeService.recomputeOnSoftwareDeltaBatch(
                eq(recomputedTenantId),
                argThat(componentIds -> componentIds != null && componentIds.size() == 1 && componentIds.contains(componentId))
        )).thenReturn(7);

        int total = findingRecomputeService.recomputeOnCveDeltaBatch(vulnerabilityIds);

        assertEquals(7, total);
        verify(findingComponentRecomputeService).recomputeOnSoftwareDeltaBatch(
                eq(recomputedTenantId),
                argThat(componentIds -> componentIds != null && componentIds.size() == 1 && componentIds.contains(componentId))
        );
        verify(orgCveRecordService).refreshForTenantAndVulnerabilities(
                eq(metadataOnlyTenantId),
                eq(vulnerabilityIds)
        );
        verify(orgCveRecordService, never()).refreshForTenantAndVulnerabilities(
                eq(recomputedTenantId),
                eq(vulnerabilityIds)
        );
    }

    @Test
    void applyVexDeltaBatchRefreshesMetadataOnlyForTenantsWithoutComponentRecompute() {
        UUID vulnerabilityId = UUID.randomUUID();
        UUID recomputedTenantId = UUID.randomUUID();
        UUID metadataOnlyTenantId = UUID.randomUUID();
        UUID componentId = UUID.randomUUID();
        List<UUID> vulnerabilityIds = List.of(vulnerabilityId);

        stubDeltaScope(vulnerabilityIds, recomputedTenantId, metadataOnlyTenantId, componentId);
        when(findingComponentRecomputeService.recomputeOnSoftwareDeltaBatch(
                eq(recomputedTenantId),
                argThat(componentIds -> componentIds != null && componentIds.size() == 1 && componentIds.contains(componentId))
        )).thenReturn(3);

        int total = findingRecomputeService.applyVexDeltaBatch(vulnerabilityIds, "vex-microsoft");

        assertEquals(3, total);
        verify(findingComponentRecomputeService).recomputeOnSoftwareDeltaBatch(
                eq(recomputedTenantId),
                argThat(componentIds -> componentIds != null && componentIds.size() == 1 && componentIds.contains(componentId))
        );
        verify(orgCveRecordService).refreshForTenantAndVulnerabilities(
                eq(metadataOnlyTenantId),
                eq(vulnerabilityIds)
        );
        verify(orgCveRecordService, never()).refreshForTenantAndVulnerabilities(
                eq(recomputedTenantId),
                eq(vulnerabilityIds)
        );
    }

    private void stubDeltaScope(
            List<UUID> vulnerabilityIds,
            UUID recomputedTenantId,
            UUID metadataOnlyTenantId,
            UUID componentId
    ) {
        ComponentVulnerabilityStateRepository.TenantComponentLookupRow row =
                componentLookupRow(recomputedTenantId, componentId);
        when(vulnerabilityTargetRepository.findVulnerabilityCpeRows(vulnerabilityIds, VulnerabilityTargetType.CPE))
                .thenReturn(List.of());
        when(vulnerabilityTargetRepository.findByVulnerability_IdInAndTargetType(vulnerabilityIds, VulnerabilityTargetType.PURL))
                .thenReturn(List.of());
        when(vulnerabilityTargetRepository.findByVulnerability_IdInAndTargetType(vulnerabilityIds, VulnerabilityTargetType.COORD))
                .thenReturn(List.of());
        when(vulnerabilityTargetRepository.findByVulnerability_IdInAndTargetType(vulnerabilityIds, VulnerabilityTargetType.ADVISORY_PACKAGE))
                .thenReturn(List.of());
        when(componentVulnerabilityStateRepository.findDistinctTenantComponentRowsByVulnerabilityIds(vulnerabilityIds))
                .thenReturn(List.of(row));
        when(componentVulnerabilityStateRepository.findDistinctTenantIdsByVulnerabilityIds(vulnerabilityIds))
                .thenReturn(Set.of(recomputedTenantId));
        when(orgCveRecordRepository.findDistinctTenantIdsByVulnerabilityIds(vulnerabilityIds))
                .thenReturn(Set.of(recomputedTenantId, metadataOnlyTenantId));
    }

    private ComponentVulnerabilityStateRepository.TenantComponentLookupRow componentLookupRow(
            UUID tenantId,
            UUID componentId
    ) {
        ComponentVulnerabilityStateRepository.TenantComponentLookupRow row =
                mock(ComponentVulnerabilityStateRepository.TenantComponentLookupRow.class);
        when(row.getTenantId()).thenReturn(tenantId);
        when(row.getComponentId()).thenReturn(componentId);
        return row;
    }
}
