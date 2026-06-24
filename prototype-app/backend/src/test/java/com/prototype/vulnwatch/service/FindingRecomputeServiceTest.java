package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import com.prototype.vulnwatch.domain.VulnerabilityTargetType;
import com.prototype.vulnwatch.repo.ComponentVulnerabilityStateRepository;
import com.prototype.vulnwatch.repo.InventoryComponentCpeMapRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.OrgCveRecordRepository;
import com.prototype.vulnwatch.repo.VulnerabilityTargetRepository;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class FindingRecomputeServiceTest {

    @Mock private FindingAssetRecomputeService findingAssetRecomputeService;
    @Mock private FindingComponentRecomputeService findingComponentRecomputeService;
    @Mock private FindingCorrelationProjectionService findingCorrelationProjectionService;
    @Mock private ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository;
    @Mock private InventoryComponentRepository inventoryComponentRepository;
    @Mock private InventoryComponentCpeMapRepository inventoryComponentCpeMapRepository;
    @Mock private VulnerabilityTargetRepository vulnerabilityTargetRepository;
    @Mock private OrgCveRecordRepository orgCveRecordRepository;
    @Mock private OrgCveRecordService orgCveRecordService;
    @Mock private TenantWorkRunner tenantWorkRunner;

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
        org.mockito.Mockito.lenient().when(tenantWorkRunner.runScoped(any(UUID.class), any(Supplier.class)))
                .thenAnswer(invocation -> invocation.getArgument(1, Supplier.class).get());
    }

    // -------------- pure delegations --------------

    @Test
    void recomputeOnSoftwareDeltaDelegatesToComponentService() {
        UUID tenantId = UUID.randomUUID();
        UUID componentId = UUID.randomUUID();
        when(findingComponentRecomputeService.recomputeOnSoftwareDeltaBatch(eq(tenantId), anyCollection())).thenReturn(4);

        int total = findingRecomputeService.recomputeOnSoftwareDelta(tenantId, componentId);

        assertEquals(4, total);
        verify(findingComponentRecomputeService).recomputeOnSoftwareDeltaBatch(eq(tenantId), anyCollection());
    }

    @Test
    void recomputeOnSoftwareDeltaBatchDelegatesToComponentService() {
        UUID tenantId = UUID.randomUUID();
        Set<UUID> componentIds = Set.of(UUID.randomUUID(), UUID.randomUUID());
        when(findingComponentRecomputeService.recomputeOnSoftwareDeltaBatch(tenantId, componentIds)).thenReturn(9);

        int total = findingRecomputeService.recomputeOnSoftwareDeltaBatch(tenantId, componentIds);

        assertEquals(9, total);
        verify(findingComponentRecomputeService).recomputeOnSoftwareDeltaBatch(tenantId, componentIds);
    }

    @Test
    void projectNotApplicableByCorrelationDelegatesToProjectionService() {
        Tenant tenant = new Tenant();
        NotApplicableProjection projection = new NotApplicableProjection(3, 1, java.util.Map.of("VEX", 2L));
        when(findingCorrelationProjectionService.projectNotApplicableByCorrelation(tenant)).thenReturn(projection);

        NotApplicableProjection result = findingRecomputeService.projectNotApplicableByCorrelation(tenant);

        assertEquals(projection, result);
    }

    // -------------- recomputeOnCveDelta guards & normalization --------------

    @Test
    void recomputeOnCveDeltaReturnsZeroWhenIdNull() {
        int total = findingRecomputeService.recomputeOnCveDelta(null);

        assertEquals(0, total);
        verifyNoInteractions(findingComponentRecomputeService, vulnerabilityTargetRepository,
                componentVulnerabilityStateRepository, orgCveRecordService);
    }

    @Test
    void recomputeOnCveDeltaBatchReturnsZeroForNull() {
        assertEquals(0, findingRecomputeService.recomputeOnCveDeltaBatch(null));
        verifyNoInteractions(findingComponentRecomputeService);
    }

    @Test
    void recomputeOnCveDeltaBatchReturnsZeroForEmpty() {
        assertEquals(0, findingRecomputeService.recomputeOnCveDeltaBatch(List.of()));
    }

    @Test
    void recomputeOnCveDeltaBatchFiltersOutAllNullIds() {
        // Collection containing only nulls → normalizeIds returns empty → 0
        assertEquals(0, findingRecomputeService.recomputeOnCveDeltaBatch(Arrays.asList((UUID) null, null)));
        verifyNoInteractions(findingComponentRecomputeService);
    }

    // -------------- applyVexDelta variants --------------

    @Test
    void applyVexDeltaTwoArgOverloadDelegatesToThreeArg() {
        UUID tenantId = UUID.randomUUID();
        UUID vulnId = UUID.randomUUID();
        // empty components branch → orgCveRecordService.refresh called
        stubEmptyComponentLookup(List.of(vulnId));
        when(orgCveRecordService.refreshForTenantAndVulnerabilities(eq(tenantId), eq(List.of(vulnId)))).thenReturn(2);

        int total = findingRecomputeService.applyVexDelta(tenantId, vulnId);

        assertEquals(2, total);
        verify(orgCveRecordService).refreshForTenantAndVulnerabilities(tenantId, List.of(vulnId));
    }

    @Test
    void applyVexDeltaReturnsZeroForNullTenant() {
        UUID vulnId = UUID.randomUUID();
        assertEquals(0, findingRecomputeService.applyVexDelta(null, vulnId, "src"));
        verifyNoInteractions(findingComponentRecomputeService, orgCveRecordService);
    }

    @Test
    void applyVexDeltaReturnsZeroForNullVulnerability() {
        UUID tenantId = UUID.randomUUID();
        assertEquals(0, findingRecomputeService.applyVexDelta(tenantId, null, "src"));
        verifyNoInteractions(findingComponentRecomputeService, orgCveRecordService);
    }

    @Test
    void applyVexDeltaWithComponentsRecomputesAndDoesNotRefreshMetadata() {
        UUID tenantId = UUID.randomUUID();
        UUID vulnId = UUID.randomUUID();
        UUID componentId = UUID.randomUUID();
        List<UUID> ids = List.of(vulnId);

        var cvsRow = cvsLookupRow(tenantId, componentId);
        stubEmptyTargets(ids);
        when(componentVulnerabilityStateRepository.findDistinctTenantComponentRowsByVulnerabilityIds(ids))
                .thenReturn(List.of(cvsRow));
        when(findingComponentRecomputeService.recomputeOnSoftwareDeltaBatch(
                eq(tenantId),
                argThat(c -> c != null && c.contains(componentId))
        )).thenReturn(11);

        int total = findingRecomputeService.applyVexDelta(tenantId, vulnId, "vex-src");

        assertEquals(11, total);
        verify(orgCveRecordService, never()).refreshForTenantAndVulnerabilities(any(UUID.class), anyCollection());
    }

    @Test
    void applyVexDeltaForVulnerabilityReturnsZeroForNullId() {
        assertEquals(0, findingRecomputeService.applyVexDeltaForVulnerability(null, "src"));
    }

    @Test
    void applyVexDeltaForVulnerabilityDelegatesToBatch() {
        UUID vulnId = UUID.randomUUID();
        UUID tenantId = UUID.randomUUID();
        UUID componentId = UUID.randomUUID();
        List<UUID> ids = List.of(vulnId);

        var cvsRow = cvsLookupRow(tenantId, componentId);
        stubEmptyTargets(ids);
        when(componentVulnerabilityStateRepository.findDistinctTenantComponentRowsByVulnerabilityIds(ids))
                .thenReturn(List.of(cvsRow));
        when(componentVulnerabilityStateRepository.findDistinctTenantIdsByVulnerabilityIds(ids))
                .thenReturn(Set.of(tenantId));
        when(orgCveRecordRepository.findDistinctTenantIdsByVulnerabilityIds(ids))
                .thenReturn(Set.of(tenantId));
        when(findingComponentRecomputeService.recomputeOnSoftwareDeltaBatch(eq(tenantId), any())).thenReturn(6);

        int total = findingRecomputeService.applyVexDeltaForVulnerability(vulnId, "src");

        assertEquals(6, total);
    }

    @Test
    void applyVexDeltaBatchReturnsZeroForNull() {
        assertEquals(0, findingRecomputeService.applyVexDeltaBatch(null, "src"));
    }

    @Test
    void applyVexDeltaBatchReturnsZeroForEmpty() {
        assertEquals(0, findingRecomputeService.applyVexDeltaBatch(List.of(), "src"));
    }

    // -------------- refreshMetadataForVulnerabilityBatch --------------

    @Test
    void refreshMetadataForVulnerabilityBatchReturnsZeroForNull() {
        assertEquals(0, findingRecomputeService.refreshMetadataForVulnerabilityBatch(null));
    }

    @Test
    void refreshMetadataForVulnerabilityBatchReturnsZeroForEmpty() {
        assertEquals(0, findingRecomputeService.refreshMetadataForVulnerabilityBatch(Collections.emptyList()));
    }

    @Test
    void refreshMetadataForVulnerabilityBatchIteratesAllTenants() {
        UUID vulnId = UUID.randomUUID();
        UUID tenantA = UUID.randomUUID();
        UUID tenantB = UUID.randomUUID();
        List<UUID> ids = List.of(vulnId);

        when(componentVulnerabilityStateRepository.findDistinctTenantIdsByVulnerabilityIds(ids))
                .thenReturn(Set.of(tenantA));
        when(orgCveRecordRepository.findDistinctTenantIdsByVulnerabilityIds(ids))
                .thenReturn(Set.of(tenantB));
        when(orgCveRecordService.refreshForTenantAndVulnerabilities(any(UUID.class), eq(ids))).thenReturn(3);

        int total = findingRecomputeService.refreshMetadataForVulnerabilityBatch(ids);

        assertEquals(6, total);
        verify(orgCveRecordService).refreshForTenantAndVulnerabilities(tenantA, ids);
        verify(orgCveRecordService).refreshForTenantAndVulnerabilities(tenantB, ids);
    }

    // -------------- refreshLifecycleForComponents --------------

    @Test
    void refreshLifecycleForComponentsReturnsZeroForNullTenant() {
        assertEquals(0, findingRecomputeService.refreshLifecycleForComponents(null, List.of(UUID.randomUUID())));
        verifyNoInteractions(componentVulnerabilityStateRepository, orgCveRecordService);
    }

    @Test
    void refreshLifecycleForComponentsReturnsZeroForNullComponentIds() {
        UUID tenantId = UUID.randomUUID();
        assertEquals(0, findingRecomputeService.refreshLifecycleForComponents(tenantId, null));
    }

    @Test
    void refreshLifecycleForComponentsReturnsZeroForEmptyComponentIds() {
        UUID tenantId = UUID.randomUUID();
        assertEquals(0, findingRecomputeService.refreshLifecycleForComponents(tenantId, List.of()));
    }

    @Test
    void refreshLifecycleForComponentsReturnsZeroWhenNoVulnerabilitiesFound() {
        UUID tenantId = UUID.randomUUID();
        UUID componentId = UUID.randomUUID();
        when(componentVulnerabilityStateRepository.findDistinctVulnerabilityIdsByTenantIdAndComponentIds(
                eq(tenantId), any())).thenReturn(Set.of());

        int total = findingRecomputeService.refreshLifecycleForComponents(tenantId, List.of(componentId));

        assertEquals(0, total);
        verify(orgCveRecordService, never()).refreshForTenantAndVulnerabilities(any(UUID.class), anyCollection());
    }

    @Test
    void refreshLifecycleForComponentsRefreshesOrgCveRecordsForFoundVulns() {
        UUID tenantId = UUID.randomUUID();
        UUID componentId = UUID.randomUUID();
        UUID vulnId = UUID.randomUUID();
        when(componentVulnerabilityStateRepository.findDistinctVulnerabilityIdsByTenantIdAndComponentIds(
                eq(tenantId), any())).thenReturn(Set.of(vulnId));
        when(orgCveRecordService.refreshForTenantAndVulnerabilities(eq(tenantId), eq(Set.of(vulnId))))
                .thenReturn(2);

        int total = findingRecomputeService.refreshLifecycleForComponents(tenantId, List.of(componentId));

        assertEquals(2, total);
        verify(orgCveRecordService).refreshForTenantAndVulnerabilities(tenantId, Set.of(vulnId));
    }

    // -------------- collectAffectedComponentsByTenant: each lookup branch --------------

    @Test
    void recomputeOnCveDeltaCollectsComponentsViaCpeLookup() {
        UUID vulnId = UUID.randomUUID();
        UUID cpeId = UUID.randomUUID();
        UUID tenantId = UUID.randomUUID();
        UUID componentId = UUID.randomUUID();
        List<UUID> ids = List.of(vulnId);

        var cpeR = cpeRow(vulnId, cpeId);
        var cpeMapR = cpeMapRow(tenantId, componentId);
        when(vulnerabilityTargetRepository.findVulnerabilityCpeRows(ids, VulnerabilityTargetType.CPE))
                .thenReturn(List.of(cpeR));
        when(inventoryComponentCpeMapRepository.findDistinctTenantComponentRowsByCpeIds(any()))
                .thenReturn(List.of(cpeMapR));
        when(vulnerabilityTargetRepository.findByVulnerability_IdInAndTargetType(ids, VulnerabilityTargetType.PURL))
                .thenReturn(List.of());
        when(vulnerabilityTargetRepository.findByVulnerability_IdInAndTargetType(ids, VulnerabilityTargetType.COORD))
                .thenReturn(List.of());
        when(vulnerabilityTargetRepository.findByVulnerability_IdInAndTargetType(ids, VulnerabilityTargetType.ADVISORY_PACKAGE))
                .thenReturn(List.of());
        when(componentVulnerabilityStateRepository.findDistinctTenantComponentRowsByVulnerabilityIds(ids))
                .thenReturn(List.of());
        when(componentVulnerabilityStateRepository.findDistinctTenantIdsByVulnerabilityIds(ids))
                .thenReturn(Set.of(tenantId));
        when(orgCveRecordRepository.findDistinctTenantIdsByVulnerabilityIds(ids))
                .thenReturn(Set.of(tenantId));
        when(findingComponentRecomputeService.recomputeOnSoftwareDeltaBatch(
                eq(tenantId),
                argThat(c -> c != null && c.contains(componentId))
        )).thenReturn(1);

        int total = findingRecomputeService.recomputeOnCveDelta(vulnId);

        assertEquals(1, total);
    }

    @Test
    void recomputeOnCveDeltaCollectsComponentsViaPurlLookup() {
        UUID vulnId = UUID.randomUUID();
        UUID tenantId = UUID.randomUUID();
        UUID componentId = UUID.randomUUID();
        List<UUID> ids = List.of(vulnId);

        when(vulnerabilityTargetRepository.findVulnerabilityCpeRows(ids, VulnerabilityTargetType.CPE))
                .thenReturn(List.of());
        var compRow = componentLookupRow(tenantId, componentId);
        when(vulnerabilityTargetRepository.findByVulnerability_IdInAndTargetType(ids, VulnerabilityTargetType.PURL))
                .thenReturn(List.of(target("pkg:npm/foo@1.0")));
        when(vulnerabilityTargetRepository.findByVulnerability_IdInAndTargetType(ids, VulnerabilityTargetType.COORD))
                .thenReturn(List.of());
        when(vulnerabilityTargetRepository.findByVulnerability_IdInAndTargetType(ids, VulnerabilityTargetType.ADVISORY_PACKAGE))
                .thenReturn(List.of());
        when(inventoryComponentRepository.findDistinctTenantComponentRowsByNormalizedPurlIn(any()))
                .thenReturn(List.of(compRow));
        when(componentVulnerabilityStateRepository.findDistinctTenantComponentRowsByVulnerabilityIds(ids))
                .thenReturn(List.of());
        when(componentVulnerabilityStateRepository.findDistinctTenantIdsByVulnerabilityIds(ids))
                .thenReturn(Set.of(tenantId));
        when(orgCveRecordRepository.findDistinctTenantIdsByVulnerabilityIds(ids))
                .thenReturn(Set.of(tenantId));
        when(findingComponentRecomputeService.recomputeOnSoftwareDeltaBatch(
                eq(tenantId),
                argThat(c -> c != null && c.contains(componentId))
        )).thenReturn(1);

        int total = findingRecomputeService.recomputeOnCveDelta(vulnId);

        assertEquals(1, total);
        verify(inventoryComponentRepository).findDistinctTenantComponentRowsByNormalizedPurlIn(any());
    }

    @Test
    void recomputeOnCveDeltaCollectsComponentsViaCoordAndAdvisoryLookup() {
        UUID vulnId = UUID.randomUUID();
        UUID tenantId = UUID.randomUUID();
        UUID componentId = UUID.randomUUID();
        List<UUID> ids = List.of(vulnId);

        when(vulnerabilityTargetRepository.findVulnerabilityCpeRows(ids, VulnerabilityTargetType.CPE))
                .thenReturn(List.of());
        when(vulnerabilityTargetRepository.findByVulnerability_IdInAndTargetType(ids, VulnerabilityTargetType.PURL))
                .thenReturn(List.of());
        var compRow = componentLookupRow(tenantId, componentId);
        when(vulnerabilityTargetRepository.findByVulnerability_IdInAndTargetType(ids, VulnerabilityTargetType.COORD))
                .thenReturn(List.of(target("group:artifact:1.0")));
        when(vulnerabilityTargetRepository.findByVulnerability_IdInAndTargetType(ids, VulnerabilityTargetType.ADVISORY_PACKAGE))
                .thenReturn(List.of(target("advisory:foo")));
        when(inventoryComponentRepository.findDistinctTenantComponentRowsByCoordKeyIn(any()))
                .thenReturn(List.of(compRow));
        when(componentVulnerabilityStateRepository.findDistinctTenantComponentRowsByVulnerabilityIds(ids))
                .thenReturn(List.of());
        when(componentVulnerabilityStateRepository.findDistinctTenantIdsByVulnerabilityIds(ids))
                .thenReturn(Set.of(tenantId));
        when(orgCveRecordRepository.findDistinctTenantIdsByVulnerabilityIds(ids))
                .thenReturn(Set.of(tenantId));
        when(findingComponentRecomputeService.recomputeOnSoftwareDeltaBatch(eq(tenantId), any()))
                .thenReturn(1);

        int total = findingRecomputeService.recomputeOnCveDelta(vulnId);

        assertEquals(1, total);
        verify(inventoryComponentRepository).findDistinctTenantComponentRowsByCoordKeyIn(any());
    }

    @Test
    void recomputeOnCveDeltaSkipsCpeLookupWhenAllCpeIdsNull() {
        UUID vulnId = UUID.randomUUID();
        List<UUID> ids = List.of(vulnId);

        var nullCpe = cpeRow(vulnId, null);
        // CPE row with null cpeId is filtered out → cpeIds set empty → no CpeMap query
        when(vulnerabilityTargetRepository.findVulnerabilityCpeRows(ids, VulnerabilityTargetType.CPE))
                .thenReturn(List.of(nullCpe));
        stubEmptyTargets(ids);
        when(componentVulnerabilityStateRepository.findDistinctTenantComponentRowsByVulnerabilityIds(ids))
                .thenReturn(List.of());
        when(componentVulnerabilityStateRepository.findDistinctTenantIdsByVulnerabilityIds(ids))
                .thenReturn(Set.of());
        when(orgCveRecordRepository.findDistinctTenantIdsByVulnerabilityIds(ids))
                .thenReturn(Set.of());

        int total = findingRecomputeService.recomputeOnCveDelta(vulnId);

        assertEquals(0, total);
        verify(inventoryComponentCpeMapRepository, never()).findDistinctTenantComponentRowsByCpeIds(any());
    }

    @Test
    void recomputeOnCveDeltaSkipsPurlLookupWhenAllKeysBlank() {
        UUID vulnId = UUID.randomUUID();
        List<UUID> ids = List.of(vulnId);

        when(vulnerabilityTargetRepository.findVulnerabilityCpeRows(ids, VulnerabilityTargetType.CPE))
                .thenReturn(List.of());
        // Blank/null keys are filtered out
        when(vulnerabilityTargetRepository.findByVulnerability_IdInAndTargetType(ids, VulnerabilityTargetType.PURL))
                .thenReturn(List.of(target("   "), target(null)));
        when(vulnerabilityTargetRepository.findByVulnerability_IdInAndTargetType(ids, VulnerabilityTargetType.COORD))
                .thenReturn(List.of());
        when(vulnerabilityTargetRepository.findByVulnerability_IdInAndTargetType(ids, VulnerabilityTargetType.ADVISORY_PACKAGE))
                .thenReturn(List.of());
        when(componentVulnerabilityStateRepository.findDistinctTenantComponentRowsByVulnerabilityIds(ids))
                .thenReturn(List.of());
        when(componentVulnerabilityStateRepository.findDistinctTenantIdsByVulnerabilityIds(ids))
                .thenReturn(Set.of());
        when(orgCveRecordRepository.findDistinctTenantIdsByVulnerabilityIds(ids))
                .thenReturn(Set.of());

        int total = findingRecomputeService.recomputeOnCveDelta(vulnId);

        assertEquals(0, total);
        verify(inventoryComponentRepository, never()).findDistinctTenantComponentRowsByNormalizedPurlIn(any());
        verify(inventoryComponentRepository, never()).findDistinctTenantComponentRowsByCoordKeyIn(any());
    }

    @Test
    void recomputeOnCveDeltaIgnoresLookupRowsWithNullIds() {
        UUID vulnId = UUID.randomUUID();
        List<UUID> ids = List.of(vulnId);

        // All lookup rows have null tenant or null component → addComponentLookupRow no-ops
        when(vulnerabilityTargetRepository.findVulnerabilityCpeRows(ids, VulnerabilityTargetType.CPE))
                .thenReturn(List.of());
        stubEmptyTargets(ids);
        var nullTenantRow = cvsLookupRow(null, UUID.randomUUID());
        var nullComponentRow = cvsLookupRow(UUID.randomUUID(), null);
        when(componentVulnerabilityStateRepository.findDistinctTenantComponentRowsByVulnerabilityIds(ids))
                .thenReturn(List.of(nullTenantRow, nullComponentRow));
        when(componentVulnerabilityStateRepository.findDistinctTenantIdsByVulnerabilityIds(ids))
                .thenReturn(Set.of());
        when(orgCveRecordRepository.findDistinctTenantIdsByVulnerabilityIds(ids))
                .thenReturn(Set.of());

        int total = findingRecomputeService.recomputeOnCveDelta(vulnId);

        assertEquals(0, total);
        verify(findingComponentRecomputeService, never()).recomputeOnSoftwareDeltaBatch(any(), any());
    }

    // -------------- helpers --------------

    private void stubEmptyComponentLookup(List<UUID> ids) {
        stubEmptyTargets(ids);
        when(componentVulnerabilityStateRepository.findDistinctTenantComponentRowsByVulnerabilityIds(ids))
                .thenReturn(List.of());
    }

    private void stubEmptyTargets(List<UUID> ids) {
        when(vulnerabilityTargetRepository.findVulnerabilityCpeRows(ids, VulnerabilityTargetType.CPE))
                .thenReturn(List.of());
        when(vulnerabilityTargetRepository.findByVulnerability_IdInAndTargetType(ids, VulnerabilityTargetType.PURL))
                .thenReturn(List.of());
        when(vulnerabilityTargetRepository.findByVulnerability_IdInAndTargetType(ids, VulnerabilityTargetType.COORD))
                .thenReturn(List.of());
        when(vulnerabilityTargetRepository.findByVulnerability_IdInAndTargetType(ids, VulnerabilityTargetType.ADVISORY_PACKAGE))
                .thenReturn(List.of());
    }

    private VulnerabilityTargetRepository.VulnerabilityCpeRow cpeRow(UUID vulnId, UUID cpeId) {
        VulnerabilityTargetRepository.VulnerabilityCpeRow row =
                mock(VulnerabilityTargetRepository.VulnerabilityCpeRow.class);
        when(row.getVulnerabilityId()).thenReturn(vulnId);
        when(row.getCpeId()).thenReturn(cpeId);
        return row;
    }

    private InventoryComponentCpeMapRepository.TenantComponentRow cpeMapRow(UUID tenantId, UUID componentId) {
        InventoryComponentCpeMapRepository.TenantComponentRow row =
                mock(InventoryComponentCpeMapRepository.TenantComponentRow.class);
        when(row.getTenantId()).thenReturn(tenantId);
        when(row.getComponentId()).thenReturn(componentId);
        return row;
    }

    private InventoryComponentRepository.TenantComponentLookupRow componentLookupRow(UUID tenantId, UUID componentId) {
        InventoryComponentRepository.TenantComponentLookupRow row =
                mock(InventoryComponentRepository.TenantComponentLookupRow.class);
        when(row.getTenantId()).thenReturn(tenantId);
        when(row.getComponentId()).thenReturn(componentId);
        return row;
    }

    private ComponentVulnerabilityStateRepository.TenantComponentLookupRow cvsLookupRow(UUID tenantId, UUID componentId) {
        ComponentVulnerabilityStateRepository.TenantComponentLookupRow row =
                mock(ComponentVulnerabilityStateRepository.TenantComponentLookupRow.class);
        when(row.getTenantId()).thenReturn(tenantId);
        when(row.getComponentId()).thenReturn(componentId);
        return row;
    }

    private VulnerabilityTarget target(String normalizedKey) {
        VulnerabilityTarget t = new VulnerabilityTarget();
        t.setNormalizedTargetKey(normalizedKey);
        return t;
    }
}
