package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class FindingCorrelationProjectionServiceTest {

    @Mock
    private InventoryComponentRepository inventoryComponentRepository;

    @Mock
    private FindingRepository findingRepository;

    @Mock
    private CorrelationCandidateService correlationCandidateService;

    @Mock
    private RiskPolicyService riskPolicyService;

    @Mock
    private PrecedenceResolverService precedenceResolverService;

    @Mock
    private FindingCorrelationAnalysisService findingCorrelationAnalysisService;

    private FindingCorrelationProjectionService findingCorrelationProjectionService;

    @BeforeEach
    void setUp() {
        findingCorrelationProjectionService = new FindingCorrelationProjectionService(
                inventoryComponentRepository,
                findingRepository,
                correlationCandidateService,
                riskPolicyService,
                precedenceResolverService,
                findingCorrelationAnalysisService
        );
    }

    @Test
    void projectNotApplicableByCorrelationReturnsEmptyProjectionWhenNoActiveComponents() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());

        when(inventoryComponentRepository.findByTenantAndComponentStatusOrderByLastObservedAtDesc(
                org.mockito.ArgumentMatchers.eq(tenant),
                org.mockito.ArgumentMatchers.any()
        )).thenReturn(List.of());

        NotApplicableProjection projection =
                findingCorrelationProjectionService.projectNotApplicableByCorrelation(tenant);

        assertEquals(0, projection.neverOpenedNotApplicable());
        assertEquals(0, projection.deferredUnderInvestigation());
        assertEquals(Map.of(), projection.categories());
    }

    @Test
    void projectNotApplicableByCorrelationCountsNotAffectedAndUnknownWithoutExistingFinding() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        InventoryComponent component = mock(InventoryComponent.class);
        when(component.getId()).thenReturn(UUID.randomUUID());

        UUID notAffectedVulnerabilityId = UUID.randomUUID();
        UUID unknownVulnerabilityId = UUID.randomUUID();
        VulnerabilityTarget target = mock(VulnerabilityTarget.class);
        when(target.getSource()).thenReturn("ghsa");

        CorrelationCandidateService.CandidateBundle bundle =
                new CorrelationCandidateService.CandidateBundle(
                        Map.of(),
                        Map.of(),
                        Map.of(),
                        Map.of(),
                        Map.of(),
                        Map.of(),
                        Map.of(),
                        Map.of(),
                        Map.of(),
                        Map.of()
                );
        CorrelationCandidateService.CandidateMatch candidateMatch =
                new CorrelationCandidateService.CandidateMatch(target, "cpe-match", 1, 0.9, Map.of());
        PrecedenceResolverService.CandidateDecision notAffectedDecision =
                new PrecedenceResolverService.CandidateDecision(
                        target,
                        "cpe-match",
                        1,
                        0.9,
                        Map.of(),
                        new ApplicabilityDecisionService.ApplicabilityDecision(
                                ApplicabilityDecisionService.ApplicabilityResult.FALSE,
                                "vex_not_affected",
                                Map.of()
                        )
                );
        PrecedenceResolverService.CandidateDecision unknownDecision =
                new PrecedenceResolverService.CandidateDecision(
                        target,
                        "cpe-match",
                        1,
                        0.8,
                        Map.of(),
                        new ApplicabilityDecisionService.ApplicabilityDecision(
                                ApplicabilityDecisionService.ApplicabilityResult.UNKNOWN,
                                "under_investigation_pending_vendor_confirmation",
                                Map.of()
                        )
                );
        PrecedenceResolverService.PrecedenceResolution notAffectedResolution =
                new PrecedenceResolverService.PrecedenceResolution(
                        PrecedenceResolverService.FinalState.NOT_AFFECTED,
                        notAffectedDecision,
                        "highest_precedence_not_affected",
                        List.of(),
                        List.of(),
                        Map.of()
                );
        PrecedenceResolverService.PrecedenceResolution unknownResolution =
                new PrecedenceResolverService.PrecedenceResolution(
                        PrecedenceResolverService.FinalState.UNKNOWN,
                        unknownDecision,
                        "unknown_pending_review",
                        List.of(),
                        List.of(),
                        Map.of()
                );

        when(inventoryComponentRepository.findByTenantAndComponentStatusOrderByLastObservedAtDesc(
                org.mockito.ArgumentMatchers.eq(tenant),
                org.mockito.ArgumentMatchers.any()
        )).thenReturn(List.of(component));
        when(correlationCandidateService.buildCandidateBundle(List.of(component))).thenReturn(bundle);
        when(correlationCandidateService.candidatesForComponent(component, bundle)).thenReturn(List.of(candidateMatch));
        when(findingRepository.findByTenantOrderByUpdatedAtDesc(tenant)).thenReturn(List.of());
        when(riskPolicyService.getOrCreate(tenant)).thenReturn(new com.prototype.vulnwatch.domain.RiskPolicy());
        when(findingCorrelationAnalysisService.buildCandidateDecisionsByVulnerability(
                org.mockito.ArgumentMatchers.eq(component),
                org.mockito.ArgumentMatchers.eq(List.of(candidateMatch)),
                org.mockito.ArgumentMatchers.any()
        )).thenReturn(Map.of(
                notAffectedVulnerabilityId, List.of(notAffectedDecision),
                unknownVulnerabilityId, List.of(unknownDecision)
        ));
        when(precedenceResolverService.resolve(List.of(notAffectedDecision))).thenReturn(notAffectedResolution);
        when(precedenceResolverService.resolve(List.of(unknownDecision))).thenReturn(unknownResolution);
        when(findingCorrelationAnalysisService.categorizeNotApplicableReason(
                "vex_not_affected",
                "highest_precedence_not_affected",
                "ghsa"
        )).thenReturn("VEX Not Affected");

        NotApplicableProjection projection =
                findingCorrelationProjectionService.projectNotApplicableByCorrelation(tenant);

        assertEquals(1, projection.neverOpenedNotApplicable());
        assertEquals(1, projection.deferredUnderInvestigation());
        assertEquals(Map.of("VEX Not Affected", 1L), projection.categories());
    }
}
