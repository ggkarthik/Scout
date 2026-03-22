package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.VulnerabilityTargetType;
import com.prototype.vulnwatch.repo.ComponentVulnerabilityStateRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.InventoryComponentCpeMapRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.OrgCveRecordRepository;
import com.prototype.vulnwatch.repo.VulnerabilityConfigExprRepository;
import com.prototype.vulnwatch.repo.VulnerabilityTargetRepository;
import jakarta.persistence.EntityManager;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.Mockito;

@ExtendWith(MockitoExtension.class)
class FindingServiceDeltaRefreshTest {

    @Mock
    private FindingRepository findingRepository;

    @Mock
    private ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository;

    @Mock
    private InventoryComponentRepository inventoryComponentRepository;

    @Mock
    private InventoryComponentCpeMapRepository inventoryComponentCpeMapRepository;

    @Mock
    private VulnerabilityTargetRepository vulnerabilityTargetRepository;

    @Mock
    private CorrelationCandidateService correlationCandidateService;

    @Mock
    private RiskPolicyService riskPolicyService;

    @Mock
    private RiskScoringService riskScoringService;

    @Mock
    private FindingWorkflowService findingWorkflowService;

    @Mock
    private ApplicabilityDecisionService applicabilityDecisionService;

    @Mock
    private ImpactEvaluationService impactEvaluationService;

    @Mock
    private VexAssertionMatchService vexAssertionMatchService;

    @Mock
    private FindingEvidenceService findingEvidenceService;

    @Mock
    private NvdConfigurationDecisionService nvdConfigurationDecisionService;

    @Mock
    private PrecedenceResolverService precedenceResolverService;

    @Mock
    private VulnerabilityConfigExprRepository vulnerabilityConfigExprRepository;

    @Mock
    private OrgCveRecordRepository orgCveRecordRepository;

    @Mock
    private OrgCveRecordService orgCveRecordService;

    @Mock
    private EntityManager entityManager;

    private FindingService findingService;

    @BeforeEach
    void setUp() {
        findingService = Mockito.spy(new FindingService(
                findingRepository,
                componentVulnerabilityStateRepository,
                inventoryComponentRepository,
                inventoryComponentCpeMapRepository,
                vulnerabilityTargetRepository,
                correlationCandidateService,
                riskPolicyService,
                riskScoringService,
                findingWorkflowService,
                applicabilityDecisionService,
                impactEvaluationService,
                vexAssertionMatchService,
                findingEvidenceService,
                nvdConfigurationDecisionService,
                precedenceResolverService,
                vulnerabilityConfigExprRepository,
                orgCveRecordRepository,
                orgCveRecordService,
                new ObjectMapper(),
                entityManager
        ));
    }

    @Test
    void recomputeOnCveDeltaBatchRefreshesMetadataOnlyForTenantsWithoutComponentRecompute() {
        UUID vulnerabilityId = UUID.randomUUID();
        UUID recomputedTenantId = UUID.randomUUID();
        UUID metadataOnlyTenantId = UUID.randomUUID();
        UUID componentId = UUID.randomUUID();
        List<UUID> vulnerabilityIds = List.of(vulnerabilityId);

        stubDeltaScope(vulnerabilityIds, recomputedTenantId, metadataOnlyTenantId, componentId);
        doReturn(7).when(findingService).recomputeOnSoftwareDeltaBatch(
                eq(recomputedTenantId),
                argThat(componentIds -> componentIds != null && componentIds.size() == 1 && componentIds.contains(componentId))
        );

        int total = findingService.recomputeOnCveDeltaBatch(vulnerabilityIds);

        assertEquals(7, total);
        verify(findingService).recomputeOnSoftwareDeltaBatch(
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
        doReturn(3).when(findingService).recomputeOnSoftwareDeltaBatch(
                eq(recomputedTenantId),
                argThat(componentIds -> componentIds != null && componentIds.size() == 1 && componentIds.contains(componentId))
        );

        int total = findingService.applyVexDeltaBatch(vulnerabilityIds, "vex-microsoft");

        assertEquals(3, total);
        verify(findingService).recomputeOnSoftwareDeltaBatch(
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
