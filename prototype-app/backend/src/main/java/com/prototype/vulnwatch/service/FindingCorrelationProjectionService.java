package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;

@Service
public class FindingCorrelationProjectionService {

    private final InventoryComponentRepository inventoryComponentRepository;
    private final FindingRepository findingRepository;
    private final CorrelationCandidateService correlationCandidateService;
    private final RiskPolicyService riskPolicyService;
    private final PrecedenceResolverService precedenceResolverService;
    private final FindingCorrelationAnalysisService findingCorrelationAnalysisService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;

    public FindingCorrelationProjectionService(
            InventoryComponentRepository inventoryComponentRepository,
            FindingRepository findingRepository,
            CorrelationCandidateService correlationCandidateService,
            RiskPolicyService riskPolicyService,
            PrecedenceResolverService precedenceResolverService,
            FindingCorrelationAnalysisService findingCorrelationAnalysisService,
            TenantSchemaExecutionService tenantSchemaExecutionService
    ) {
        this.inventoryComponentRepository = inventoryComponentRepository;
        this.findingRepository = findingRepository;
        this.correlationCandidateService = correlationCandidateService;
        this.riskPolicyService = riskPolicyService;
        this.precedenceResolverService = precedenceResolverService;
        this.findingCorrelationAnalysisService = findingCorrelationAnalysisService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
    }

    public NotApplicableProjection projectNotApplicableByCorrelation(Tenant tenant) {
        List<InventoryComponent> components = tenantSchemaExecutionService.run(
                tenant,
                () -> inventoryComponentRepository.findByComponentStatusOrderByLastObservedAtDesc(InventoryComponentStatus.ACTIVE)
        );
        if (components.isEmpty()) {
            return new NotApplicableProjection(0, 0, Map.of());
        }

        CorrelationCandidateService.CandidateBundle candidateBundle =
                correlationCandidateService.buildCandidateBundle(components);
        Map<String, Finding> existingByKey = new HashMap<>();
        for (Finding finding : tenantSchemaExecutionService.run(tenant, () -> findingRepository.findAllByOrderByUpdatedAtDesc())) {
            existingByKey.put(exposureKey(finding.getComponent().getId(), finding.getVulnerability().getId()), finding);
        }
        RiskPolicy policy = riskPolicyService.getOrCreate(tenant);

        long neverOpenedNotApplicable = 0;
        long deferredUnderInvestigation = 0;
        Map<String, Long> categories = new HashMap<>();

        for (InventoryComponent component : components) {
            List<CorrelationCandidateService.CandidateMatch> candidates =
                    correlationCandidateService.candidatesForComponent(component, candidateBundle);
            Map<UUID, List<PrecedenceResolverService.CandidateDecision>> candidateDecisionsByVulnerability =
                    findingCorrelationAnalysisService.buildCandidateDecisionsByVulnerability(component, candidates, policy);
            for (Map.Entry<UUID, List<PrecedenceResolverService.CandidateDecision>> entry : candidateDecisionsByVulnerability.entrySet()) {
                List<PrecedenceResolverService.CandidateDecision> decisions = entry.getValue();
                if (decisions == null || decisions.isEmpty()) {
                    continue;
                }
                PrecedenceResolverService.PrecedenceResolution resolution = precedenceResolverService.resolve(decisions);
                PrecedenceResolverService.CandidateDecision primary = resolution.primary();
                String key = exposureKey(component.getId(), entry.getKey());
                Finding existing = existingByKey.get(key);

                if (resolution.finalState() == PrecedenceResolverService.FinalState.NOT_AFFECTED
                        && primary != null
                        && existing == null) {
                    neverOpenedNotApplicable++;
                    String category = findingCorrelationAnalysisService.categorizeNotApplicableReason(
                            primary.applicabilityDecision() == null ? null : primary.applicabilityDecision().reason(),
                            resolution.reason(),
                            primary.target() == null ? null : primary.target().getSource()
                    );
                    categories.merge(category, 1L, Long::sum);
                    continue;
                }

                if (resolution.finalState() == PrecedenceResolverService.FinalState.UNKNOWN
                        && primary != null
                        && primary.applicabilityDecision() != null
                        && existing == null) {
                    String reason = primary.applicabilityDecision().reason();
                    if (reason != null && reason.toLowerCase(java.util.Locale.ROOT).contains("under_investigation")) {
                        deferredUnderInvestigation++;
                    }
                }
            }
        }

        return new NotApplicableProjection(
                neverOpenedNotApplicable,
                deferredUnderInvestigation,
                Map.copyOf(categories)
        );
    }

    private String exposureKey(UUID componentId, UUID vulnerabilityId) {
        return componentId + "::" + vulnerabilityId;
    }
}
