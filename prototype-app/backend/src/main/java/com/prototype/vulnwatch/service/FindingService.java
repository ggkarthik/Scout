package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.ApplicabilityState;
import com.prototype.vulnwatch.domain.AnalystDisposition;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetState;
import com.prototype.vulnwatch.domain.BusinessCriticality;
import com.prototype.vulnwatch.domain.ComponentVulnerabilityState;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.ImpactState;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilityConfigExpr;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import com.prototype.vulnwatch.dto.FindingFilterValuesResponse;
import com.prototype.vulnwatch.dto.FindingPageResponse;
import com.prototype.vulnwatch.dto.FindingResponse;
import com.prototype.vulnwatch.dto.FindingWorkflowUpdateRequest;
import com.prototype.vulnwatch.repo.ComponentVulnerabilityStateRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.InventoryComponentCpeMapRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.OrgCveRecordRepository;
import com.prototype.vulnwatch.repo.VulnerabilityTargetRepository;
import com.prototype.vulnwatch.repo.VulnerabilityConfigExprRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.FlushModeType;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class FindingService {

    private static final Logger LOG = LoggerFactory.getLogger(FindingService.class);

    @Value("${app.correlation.non-cpe-create-min-confidence:0.68}")
    private double nonCpeCreateMinConfidence;

    private final FindingRepository findingRepository;
    private final ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository;
    private final InventoryComponentRepository inventoryComponentRepository;
    private final InventoryComponentCpeMapRepository inventoryComponentCpeMapRepository;
    private final VulnerabilityTargetRepository vulnerabilityTargetRepository;
    private final CorrelationCandidateService correlationCandidateService;
    private final RiskPolicyService riskPolicyService;
    private final RiskScoringService riskScoringService;
    private final FindingWorkflowService findingWorkflowService;
    private final ApplicabilityDecisionService applicabilityDecisionService;
    private final ImpactEvaluationService impactEvaluationService;
    private final VexAssertionMatchService vexAssertionMatchService;
    private final FindingEvidenceService findingEvidenceService;
    private final NvdConfigurationDecisionService nvdConfigurationDecisionService;
    private final PrecedenceResolverService precedenceResolverService;
    private final VulnerabilityConfigExprRepository vulnerabilityConfigExprRepository;
    private final OrgCveRecordRepository orgCveRecordRepository;
    private final OrgCveRecordService orgCveRecordService;
    private final ObjectMapper objectMapper;
    private final EntityManager entityManager;

    public FindingService(
            FindingRepository findingRepository,
            ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository,
            InventoryComponentRepository inventoryComponentRepository,
            InventoryComponentCpeMapRepository inventoryComponentCpeMapRepository,
            VulnerabilityTargetRepository vulnerabilityTargetRepository,
            CorrelationCandidateService correlationCandidateService,
            RiskPolicyService riskPolicyService,
            RiskScoringService riskScoringService,
            FindingWorkflowService findingWorkflowService,
            ApplicabilityDecisionService applicabilityDecisionService,
            ImpactEvaluationService impactEvaluationService,
            VexAssertionMatchService vexAssertionMatchService,
            FindingEvidenceService findingEvidenceService,
            NvdConfigurationDecisionService nvdConfigurationDecisionService,
            PrecedenceResolverService precedenceResolverService,
            VulnerabilityConfigExprRepository vulnerabilityConfigExprRepository,
            OrgCveRecordRepository orgCveRecordRepository,
            OrgCveRecordService orgCveRecordService,
            ObjectMapper objectMapper,
            EntityManager entityManager
    ) {
        this.findingRepository = findingRepository;
        this.componentVulnerabilityStateRepository = componentVulnerabilityStateRepository;
        this.inventoryComponentRepository = inventoryComponentRepository;
        this.inventoryComponentCpeMapRepository = inventoryComponentCpeMapRepository;
        this.vulnerabilityTargetRepository = vulnerabilityTargetRepository;
        this.correlationCandidateService = correlationCandidateService;
        this.riskPolicyService = riskPolicyService;
        this.riskScoringService = riskScoringService;
        this.findingWorkflowService = findingWorkflowService;
        this.applicabilityDecisionService = applicabilityDecisionService;
        this.impactEvaluationService = impactEvaluationService;
        this.vexAssertionMatchService = vexAssertionMatchService;
        this.findingEvidenceService = findingEvidenceService;
        this.nvdConfigurationDecisionService = nvdConfigurationDecisionService;
        this.precedenceResolverService = precedenceResolverService;
        this.vulnerabilityConfigExprRepository = vulnerabilityConfigExprRepository;
        this.orgCveRecordRepository = orgCveRecordRepository;
        this.orgCveRecordService = orgCveRecordService;
        this.objectMapper = objectMapper;
        this.entityManager = entityManager;
    }

    @Transactional
    public Finding saveFinding(Finding finding) {
        finding.touch();
        return findingRepository.save(finding);
    }

    @Transactional
    public int recomputeForAsset(Tenant tenant, Asset asset) {
        List<InventoryComponent> components = inventoryComponentRepository.findByAssetAndComponentStatus(asset, InventoryComponentStatus.ACTIVE);
        RiskPolicy policy = riskPolicyService.getOrCreate(tenant);
        List<Finding> existing = findingRepository.findByAsset(asset);

        if (asset.getState() != AssetState.ACTIVE) {
            for (Finding finding : existing) {
                if (finding.getStatus() != FindingStatus.RESOLVED && finding.getStatus() != FindingStatus.AUTO_CLOSED) {
                    FindingStatus previousStatus = finding.getStatus();
                    finding.setStatus(FindingStatus.RESOLVED);
                    finding.setDecisionState(FindingDecisionState.NOT_AFFECTED);
                    finding.setSuppressionReason(null);
                    finding.setSuppressedUntil(null);
                    finding.touch();
                    findingWorkflowService.appendEvent(
                            finding,
                            "AUTO_RESOLVED_ASSET_INACTIVE",
                            "system",
                            "Finding auto-resolved because asset is not active",
                            Map.of(
                                    "assetState", asset.getState().name(),
                                    "fromStatus", previousStatus.name(),
                                    "toStatus", FindingStatus.RESOLVED.name()
                            ));
                }
            }
            if (!existing.isEmpty()) {
                findingRepository.saveAll(existing);
            }
            return 0;
        }

        Map<String, Finding> existingByKey = new HashMap<>();
        for (Finding finding : existing) {
            existingByKey.put(exposureKey(finding.getComponent().getId(), finding.getVulnerability().getId()), finding);
        }

        CorrelationCandidateService.CandidateBundle candidateBundle =
                correlationCandidateService.buildCandidateBundle(components);
        Set<String> activeKeys = new HashSet<>();
        Instant now = Instant.now();
        List<Finding> toPersist = new ArrayList<>();
        List<Finding> createdFindings = new ArrayList<>();
        Map<String, Long> precedenceReasonCounts = new LinkedHashMap<>();
        long staleSuppressionSignals = 0;
        long underInvestigationSignals = 0;

        for (InventoryComponent component : components) {
            List<CorrelationCandidateService.CandidateMatch> candidates =
                    correlationCandidateService.candidatesForComponent(component, candidateBundle);
            Map<UUID, List<PrecedenceResolverService.CandidateDecision>> candidateDecisionsByVulnerability =
                    buildCandidateDecisionsByVulnerability(component, candidates, policy);

            List<UUID> vulnerabilityIds = new ArrayList<>(candidateDecisionsByVulnerability.keySet());
            vulnerabilityIds.sort(UUID::compareTo);
            for (UUID vulnerabilityId : vulnerabilityIds) {
                List<PrecedenceResolverService.CandidateDecision> decisions = candidateDecisionsByVulnerability.get(vulnerabilityId);
                if (decisions == null || decisions.isEmpty()) {
                    continue;
                }
                PrecedenceResolverService.PrecedenceResolution resolution = precedenceResolverService.resolve(decisions);
                precedenceReasonCounts.merge(resolution.reason(), 1L, Long::sum);
                if (resolution.primary() != null && resolution.primary().applicabilityDecision() != null) {
                    String applicabilityReason = resolution.primary().applicabilityDecision().reason();
                    if (applicabilityReason != null) {
                        String normalized = applicabilityReason.toLowerCase(Locale.ROOT);
                        if (normalized.contains("stale_or_untrusted")) {
                            staleSuppressionSignals++;
                        }
                        if (normalized.contains("under_investigation")) {
                            underInvestigationSignals++;
                        }
                    }
                }
                ImpactEvaluationService.VexOverlayOutcome vexOverlay =
                        resolveVexOverlay(component, vulnerabilityId, null, candidates, policy);
                ImpactEvaluationService.ImpactAssessment impactAssessment =
                        impactEvaluationService.evaluate(resolution, resolution.primary(), vexOverlay);
                if (resolution.finalState() != PrecedenceResolverService.FinalState.AFFECTED
                        || resolution.primary() == null
                        || resolution.primary().applicabilityDecision() == null
                        || !resolution.primary().applicabilityDecision().isAffected()) {
                    continue;
                }
                if (!impactAssessment.findingEligible()) {
                    // VEX FIX #1: Auto-resolve existing findings when VEX says NOT_AFFECTED
                    PrecedenceResolverService.CandidateDecision selected = resolution.primary();
                    VulnerabilityTarget target = selected.target();
                    Vulnerability vulnerability = target.getVulnerability();
                    String key = exposureKey(component.getId(), vulnerability.getId());
                    Finding existingFinding = existingByKey.get(key);

                    if (existingFinding != null
                            && existingFinding.getStatus() != FindingStatus.RESOLVED
                            && existingFinding.getStatus() != FindingStatus.AUTO_CLOSED) {
                        // Resolve the existing finding (consistent with applyVexDelta logic)
                        existingFinding.setStatus(FindingStatus.RESOLVED);
                        existingFinding.setDecisionState(impactAssessment.findingDecisionState());
                        setEvidenceWithVex(existingFinding, withVexOverlayEvidence(existingFinding.getEvidence(), vexOverlay));
                        existingFinding.setLastObservedAt(now);
                        existingFinding.touch();

                        // Log the auto-resolution event
                        findingWorkflowService.appendEvent(
                            existingFinding,
                            "EXACT_IMPACT_RESOLVED",
                            "system",
                            impactAssessment.impactReasonDetail(),
                            Map.of(
                                "vexProvider", vexOverlay.provider(),
                                "vexStatus", vexOverlay.status(),
                                "vexFreshness", vexOverlay.freshness(),
                                "impactState", impactAssessment.impactState().name(),
                                "impactReason", impactAssessment.impactReason(),
                                "previousStatus", existingFinding.getStatus().name(),
                                "previousDecisionState", existingFinding.getDecisionState() != null ? existingFinding.getDecisionState().name() : "UNKNOWN",
                                "vexSource", vexOverlay.source() != null ? vexOverlay.source() : "unknown",
                                "resolvedAt", now.toString()
                            )
                        );

                        LOG.info("Resolved finding {} for component {} and vulnerability {} using canonical impact state {}",
                            existingFinding.getId(), component.getId(), vulnerability.getExternalId(),
                            impactAssessment.impactState());
                    }
                    continue;
                }

                PrecedenceResolverService.CandidateDecision selected = resolution.primary();
                String key = exposureKey(component.getId(), vulnerabilityId);
                Finding finding = existingByKey.get(key);
                PrecedenceResolverService.CandidateDecision findingSelected = selected;
                if (finding == null) {
                    findingSelected = selectAutomaticFindingCandidate(resolution, decisions);
                    if (findingSelected == null) {
                        continue;
                    }
                }
                VulnerabilityTarget target = findingSelected.target();
                Vulnerability vulnerability = target.getVulnerability();
                if (finding == null && orgCveRecordService.isActivelySuppressed(tenant, vulnerability, now)) {
                    continue;
                }

                RiskScoringService.RiskScoreOutcome riskScoreOutcome =
                        riskScoringService.score(vulnerability, policy, asset, findingSelected, resolution);
                double riskScore = riskScoreOutcome.score();
                String evidence = findingEvidenceService.buildEvidence(
                        component,
                        vulnerability,
                        target,
                        findingSelected,
                        resolution,
                        riskScoreOutcome
                );
                evidence = withVexOverlayEvidence(evidence, vexOverlay);

                if (finding == null) {
                    if (!isAutomaticFindingGenerationEnabled(policy)) {
                        continue;
                    }
                    finding = createFinding(
                            tenant,
                            asset,
                            component,
                            vulnerability,
                            findingSelected,
                            resolution,
                            riskScore,
                            evidence,
                            now,
                            policy
                    );
                    existingByKey.put(key, finding);
                    createdFindings.add(finding);
                }
                activeKeys.add(key);

                if (finding.getStatus() == FindingStatus.AUTO_CLOSED) {
                    // Keep policy auto-closed findings closed until explicitly changed by workflow/policy updates.
                    finding.setSuppressionReason(null);
                    finding.setSuppressedUntil(null);
                } else if (finding.getStatus() != FindingStatus.SUPPRESSED || isSuppressionExpired(finding, now)) {
                    finding.setStatus(FindingStatus.OPEN);
                    if (isSuppressionExpired(finding, now)) {
                        finding.setSuppressionReason(null);
                        finding.setSuppressedUntil(null);
                        findingWorkflowService.appendEvent(
                                finding,
                                "SUPPRESSION_EXPIRED",
                                "system",
                                "Suppression expired and finding reopened during recompute",
                                Map.of("reopenedAt", now));
                    }
                }
                finding.setDecisionState(impactAssessment.findingDecisionState());
                finding.setMatchedBy(findingSelected.matchedBy());
                finding.setRiskScore(riskScore);
                finding.setDueAt(deriveSlaDueAt(finding.getFirstObservedAt(), riskScore, asset, policy));
                finding.setConfidenceScore(findingSelected.confidence());
                setEvidenceWithVex(finding, evidence);
                finding.setPrecedenceTrace(toJson(resolution.precedenceTrace()));
                finding.setLastObservedAt(now);
                finding.touch();
                toPersist.add(finding);
            }
        }

        for (Finding finding : existing) {
            String key = exposureKey(finding.getComponent().getId(), finding.getVulnerability().getId());
            if (!activeKeys.contains(key)
                    && finding.getStatus() != FindingStatus.RESOLVED
                    && finding.getStatus() != FindingStatus.AUTO_CLOSED) {
                FindingStatus previousStatus = finding.getStatus();
                finding.setStatus(FindingStatus.RESOLVED);
                finding.setDecisionState(FindingDecisionState.NOT_AFFECTED);
                finding.setSuppressionReason(null);
                finding.setSuppressedUntil(null);
                finding.touch();
                findingWorkflowService.appendEvent(
                        finding,
                        "AUTO_RESOLVED_NOT_OBSERVED",
                        "system",
                        "Finding auto-resolved because it is not observed in latest inventory correlation",
                        Map.of(
                                "fromStatus", previousStatus.name(),
                                "toStatus", FindingStatus.RESOLVED.name()
                        ));
                toPersist.add(finding);
            }
        }

        if (!toPersist.isEmpty()) {
            findingRepository.saveAll(toPersist);
            for (Finding finding : createdFindings) {
                findingWorkflowService.appendEvent(
                        finding,
                        "CREATED_BY_CORRELATION",
                        "system",
                        "Finding created from deterministic inventory-to-vulnerability correlation",
                        Map.of(
                                "matchedBy", finding.getMatchedBy(),
                                "riskScore", finding.getRiskScore(),
                                "confidenceScore", finding.getConfidenceScore()
                        )
                );
            }
        }
        LOG.info(
                "Correlation diagnostics tenant={} asset={} activeFindings={} staleSuppressionSignals={} underInvestigationSignals={} precedenceReasons={}",
                tenant.getName(),
                asset.getIdentifier(),
                activeKeys.size(),
                staleSuppressionSignals,
                underInvestigationSignals,
                precedenceReasonCounts);
        return activeKeys.size();
    }

    @Transactional
    public int recomputeForAssets(List<Asset> assets) {
        int total = 0;
        for (Asset asset : assets) {
            total += recomputeForAsset(asset.getTenant(), asset);
        }
        return total;
    }

    @Transactional
    public int recomputeOnSoftwareDelta(UUID tenantId, UUID componentId) {
        if (tenantId == null || componentId == null) {
            return 0;
        }
        return recomputeOnSoftwareDeltaBatch(tenantId, List.of(componentId));
    }

    @Transactional
    public int recomputeOnSoftwareDeltaBatch(UUID tenantId, Collection<UUID> componentIds) {
        if (tenantId == null || componentIds == null || componentIds.isEmpty()) {
            return 0;
        }
        FlushModeType previousFlushMode = entityManager.getFlushMode();
        entityManager.setFlushMode(FlushModeType.COMMIT);
        try {
            List<InventoryComponent> components = inventoryComponentRepository.findAllById(componentIds).stream()
                    .filter(component -> component.getTenant() != null
                            && component.getTenant().getId() != null
                            && tenantId.equals(component.getTenant().getId()))
                    .sorted(Comparator.comparing(InventoryComponent::getId))
                    .toList();
            if (components.isEmpty()) {
                return 0;
            }
            RiskPolicy policy = riskPolicyService.getOrCreate(components.get(0).getTenant());
            CorrelationCandidateService.CandidateBundle candidateBundle =
                    correlationCandidateService.buildCandidateBundle(components);
            Set<UUID> scopedComponentIds = components.stream()
                    .map(InventoryComponent::getId)
                    .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));
            Map<UUID, List<Finding>> existingFindingsByComponentId = new HashMap<>();
            findingRepository.findByComponent_IdIn(scopedComponentIds).forEach(finding -> {
                if (finding.getComponent() == null || finding.getComponent().getId() == null) {
                    return;
                }
                existingFindingsByComponentId
                        .computeIfAbsent(finding.getComponent().getId(), ignored -> new ArrayList<>())
                        .add(finding);
            });
            Map<UUID, List<ComponentVulnerabilityState>> existingStatesByComponentId = new HashMap<>();
            componentVulnerabilityStateRepository.findByComponent_IdIn(scopedComponentIds).forEach(state -> {
                if (state.getTenant() == null || state.getTenant().getId() == null || !tenantId.equals(state.getTenant().getId())) {
                    return;
                }
                if (state.getComponent() == null || state.getComponent().getId() == null) {
                    return;
                }
                existingStatesByComponentId
                        .computeIfAbsent(state.getComponent().getId(), ignored -> new ArrayList<>())
                        .add(state);
            });
            Instant now = Instant.now();
            int total = 0;
            Set<UUID> touchedVulnerabilityIds = new LinkedHashSet<>();
            for (InventoryComponent component : components) {
                ComponentRecomputeResult result = recomputeForComponent(
                        component.getTenant(),
                        component,
                        policy,
                        now,
                        candidateBundle,
                        existingFindingsByComponentId.getOrDefault(component.getId(), List.of()),
                        existingStatesByComponentId.getOrDefault(component.getId(), List.of())
                );
                total += result.activeFindingCount();
                touchedVulnerabilityIds.addAll(result.touchedVulnerabilityIds());
            }
            entityManager.flush();
            // Component recompute is the sole owner of org-CVE projection refresh for this scope.
            if (!touchedVulnerabilityIds.isEmpty()) {
                orgCveRecordService.refreshForTenantAndVulnerabilities(tenantId, touchedVulnerabilityIds);
            }
            return total;
        } finally {
            entityManager.setFlushMode(previousFlushMode);
        }
    }

    @Transactional
    public int recomputeOnCveDelta(UUID vulnerabilityId) {
        if (vulnerabilityId == null) {
            return 0;
        }
        return recomputeOnCveDeltaBatch(List.of(vulnerabilityId));
    }

    @Transactional
    public int recomputeOnCveDeltaBatch(Collection<UUID> vulnerabilityIds) {
        List<UUID> scopedVulnerabilityIds = normalizeIds(vulnerabilityIds);
        if (scopedVulnerabilityIds.isEmpty()) {
            return 0;
        }
        Map<UUID, Set<UUID>> componentsByTenant = collectAffectedComponentsByTenant(scopedVulnerabilityIds);

        int total = 0;
        for (Map.Entry<UUID, Set<UUID>> entry : componentsByTenant.entrySet()) {
            total += recomputeOnSoftwareDeltaBatch(entry.getKey(), entry.getValue());
        }
        refreshMetadataForTenantsWithoutComponentRecompute(scopedVulnerabilityIds, componentsByTenant.keySet());
        return total;
    }

    @Transactional
    public int applyVexDelta(UUID tenantId, UUID vulnerabilityId) {
        return applyVexDelta(tenantId, vulnerabilityId, (String) null);
    }

    @Transactional
    public int applyVexDeltaForVulnerability(UUID vulnerabilityId, String sourceKey) {
        if (vulnerabilityId == null) {
            return 0;
        }
        return applyVexDeltaBatch(List.of(vulnerabilityId), sourceKey);
    }

    @Transactional
    public int applyVexDeltaBatch(Collection<UUID> vulnerabilityIds, String sourceKey) {
        List<UUID> scopedVulnerabilityIds = normalizeIds(vulnerabilityIds);
        if (scopedVulnerabilityIds.isEmpty()) {
            return 0;
        }
        Map<UUID, Set<UUID>> componentsByTenant = collectAffectedComponentsByTenant(scopedVulnerabilityIds);
        int total = 0;
        for (Map.Entry<UUID, Set<UUID>> entry : componentsByTenant.entrySet()) {
            total += recomputeOnSoftwareDeltaBatch(entry.getKey(), entry.getValue());
        }
        refreshMetadataForTenantsWithoutComponentRecompute(scopedVulnerabilityIds, componentsByTenant.keySet());
        return total;
    }

    @Transactional
    public int applyVexDelta(UUID tenantId, UUID vulnerabilityId, String sourceKey) {
        if (tenantId == null || vulnerabilityId == null) {
            return 0;
        }
        Set<UUID> affectedComponentIds = collectAffectedComponentsByTenant(List.of(vulnerabilityId)).getOrDefault(tenantId, Set.of());
        if (affectedComponentIds.isEmpty()) {
            return orgCveRecordService.refreshForTenantAndVulnerabilities(tenantId, List.of(vulnerabilityId));
        }
        return recomputeOnSoftwareDeltaBatch(tenantId, affectedComponentIds);
    }

    @Transactional
    public int refreshMetadataForVulnerabilityBatch(Collection<UUID> vulnerabilityIds) {
        List<UUID> scopedVulnerabilityIds = normalizeIds(vulnerabilityIds);
        if (scopedVulnerabilityIds.isEmpty()) {
            return 0;
        }
        int updated = 0;
        for (UUID tenantId : findTenantIdsForVulnerabilities(scopedVulnerabilityIds)) {
            updated += orgCveRecordService.refreshForTenantAndVulnerabilities(tenantId, scopedVulnerabilityIds);
        }
        return updated;
    }

    private void refreshMetadataForTenantsWithoutComponentRecompute(
            Collection<UUID> vulnerabilityIds,
            Collection<UUID> recomputedTenantIds
    ) {
        List<UUID> scopedVulnerabilityIds = normalizeIds(vulnerabilityIds);
        if (scopedVulnerabilityIds.isEmpty()) {
            return;
        }
        Set<UUID> tenantsNeedingMetadataRefresh = findTenantIdsForVulnerabilities(scopedVulnerabilityIds);
        if (recomputedTenantIds != null && !recomputedTenantIds.isEmpty()) {
            tenantsNeedingMetadataRefresh.removeAll(recomputedTenantIds);
        }
        for (UUID tenantId : tenantsNeedingMetadataRefresh) {
            orgCveRecordService.refreshForTenantAndVulnerabilities(tenantId, scopedVulnerabilityIds);
        }
    }

    @Transactional
    public int refreshLifecycleForComponents(UUID tenantId, Collection<UUID> componentIds) {
        if (tenantId == null) {
            return 0;
        }
        List<UUID> scopedComponentIds = normalizeIds(componentIds);
        if (scopedComponentIds.isEmpty()) {
            return 0;
        }
        Set<UUID> vulnerabilityIds =
                componentVulnerabilityStateRepository.findDistinctVulnerabilityIdsByTenantIdAndComponentIds(
                        tenantId,
                        scopedComponentIds
                );
        if (vulnerabilityIds.isEmpty()) {
            return 0;
        }
        return orgCveRecordService.refreshForTenantAndVulnerabilities(tenantId, vulnerabilityIds);
    }

    private Map<UUID, Set<UUID>> collectAffectedComponentsByTenant(UUID vulnerabilityId) {
        return collectAffectedComponentsByTenant(List.of(vulnerabilityId));
    }

    private Map<UUID, Set<UUID>> collectAffectedComponentsByTenant(Collection<UUID> vulnerabilityIds) {
        List<UUID> scopedVulnerabilityIds = normalizeIds(vulnerabilityIds);
        Map<UUID, Set<UUID>> componentsByTenant = new HashMap<>();
        if (scopedVulnerabilityIds.isEmpty()) {
            return componentsByTenant;
        }

        Set<UUID> cpeIds = vulnerabilityTargetRepository.findVulnerabilityCpeRows(
                        scopedVulnerabilityIds,
                        com.prototype.vulnwatch.domain.VulnerabilityTargetType.CPE
                ).stream()
                .map(com.prototype.vulnwatch.repo.VulnerabilityTargetRepository.VulnerabilityCpeRow::getCpeId)
                .filter(Objects::nonNull)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        if (!cpeIds.isEmpty()) {
            inventoryComponentCpeMapRepository.findDistinctTenantComponentRowsByCpeIds(cpeIds).forEach(row ->
                    addComponentLookupRow(componentsByTenant, row.getTenantId(), row.getComponentId()));
        }

        Set<String> purlKeys = vulnerabilityTargetRepository
                .findByVulnerability_IdInAndTargetType(
                        scopedVulnerabilityIds,
                        com.prototype.vulnwatch.domain.VulnerabilityTargetType.PURL
                ).stream()
                .map(VulnerabilityTarget::getNormalizedTargetKey)
                .filter(value -> hasText(value))
                .map(String::trim)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        if (!purlKeys.isEmpty()) {
            inventoryComponentRepository.findDistinctTenantComponentRowsByNormalizedPurlIn(purlKeys).forEach(row ->
                    addComponentLookupRow(componentsByTenant, row.getTenantId(), row.getComponentId()));
        }

        Set<String> coordKeys = vulnerabilityTargetRepository
                .findByVulnerability_IdInAndTargetType(
                        scopedVulnerabilityIds,
                        com.prototype.vulnwatch.domain.VulnerabilityTargetType.COORD
                ).stream()
                .map(VulnerabilityTarget::getNormalizedTargetKey)
                .filter(value -> hasText(value))
                .map(String::trim)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        Set<String> advisoryKeys = vulnerabilityTargetRepository
                .findByVulnerability_IdInAndTargetType(
                        scopedVulnerabilityIds,
                        com.prototype.vulnwatch.domain.VulnerabilityTargetType.ADVISORY_PACKAGE
                ).stream()
                .map(VulnerabilityTarget::getNormalizedTargetKey)
                .filter(value -> hasText(value))
                .map(String::trim)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        Set<String> allCoordKeys = new HashSet<>(coordKeys);
        allCoordKeys.addAll(advisoryKeys);
        if (!allCoordKeys.isEmpty()) {
            inventoryComponentRepository.findDistinctTenantComponentRowsByCoordKeyIn(allCoordKeys).forEach(row ->
                    addComponentLookupRow(componentsByTenant, row.getTenantId(), row.getComponentId()));
        }

        componentVulnerabilityStateRepository.findDistinctTenantComponentRowsByVulnerabilityIds(scopedVulnerabilityIds)
                .forEach(row -> addComponentLookupRow(componentsByTenant, row.getTenantId(), row.getComponentId()));

        return componentsByTenant;
    }

    private Set<UUID> findTenantIdsForVulnerabilities(Collection<UUID> vulnerabilityIds) {
        List<UUID> scopedVulnerabilityIds = normalizeIds(vulnerabilityIds);
        if (scopedVulnerabilityIds.isEmpty()) {
            return Set.of();
        }
        Set<UUID> tenantIds = new LinkedHashSet<>();
        tenantIds.addAll(componentVulnerabilityStateRepository.findDistinctTenantIdsByVulnerabilityIds(scopedVulnerabilityIds));
        tenantIds.addAll(orgCveRecordRepository.findDistinctTenantIdsByVulnerabilityIds(scopedVulnerabilityIds));
        return tenantIds;
    }

    private List<UUID> normalizeIds(Collection<UUID> ids) {
        if (ids == null || ids.isEmpty()) {
            return List.of();
        }
        return ids.stream()
                .filter(Objects::nonNull)
                .collect(Collectors.toCollection(LinkedHashSet::new))
                .stream()
                .sorted(UUID::compareTo)
                .toList();
    }

    private void addComponentLookupRow(Map<UUID, Set<UUID>> componentsByTenant, UUID tenantId, UUID componentId) {
        if (tenantId == null || componentId == null) {
            return;
        }
        componentsByTenant.computeIfAbsent(tenantId, ignored -> new HashSet<>()).add(componentId);
    }

    @Transactional(readOnly = true)
    public NotApplicableProjection projectNotApplicableByCorrelation(Tenant tenant) {
        List<InventoryComponent> components = inventoryComponentRepository
                .findByTenantAndComponentStatusOrderByLastObservedAtDesc(tenant, InventoryComponentStatus.ACTIVE);
        if (components.isEmpty()) {
            return new NotApplicableProjection(0, 0, Map.of());
        }

        CorrelationCandidateService.CandidateBundle candidateBundle =
                correlationCandidateService.buildCandidateBundle(components);
        Map<String, Finding> existingByKey = new HashMap<>();
        for (Finding finding : findingRepository.findByTenantOrderByUpdatedAtDesc(tenant)) {
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
                    buildCandidateDecisionsByVulnerability(component, candidates, policy);
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
                    String category = categorizeNotApplicableReason(
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

    public FindingPageResponse listByTenantPage(
            Tenant tenant,
            int page,
            int size,
            List<String> severity,
            List<String> status,
            List<String> decisionState,
            List<String> matchMethod,
            List<String> vexStatus,
            List<String> vexFreshness,
            List<String> vexProvider,
            Double minConfidence,
            String vulnerabilityId,
            String packageName,
            String ecosystem
    ) {
        int safePage = Math.max(0, page);
        int safeSize = Math.max(1, Math.min(200, size));
        Pageable pageable = PageRequest.of(safePage, safeSize, Sort.by(Sort.Direction.DESC, "updatedAt"));

        Specification<Finding> specification = byFilter(
                tenant,
                severity,
                status,
                decisionState,
                matchMethod,
                vexStatus,
                vexFreshness,
                vexProvider,
                minConfidence,
                vulnerabilityId,
                packageName,
                ecosystem
        );
        Page<Finding> findings = findingRepository.findAll(specification, pageable);
        return new FindingPageResponse(
                findings.getContent().stream().map(this::toResponse).toList(),
                findings.getNumber(),
                findings.getSize(),
                findings.getTotalElements(),
                findings.getTotalPages()
        );
    }

    public List<Finding> listEntitiesByTenantFilter(
            Tenant tenant,
            List<String> severity,
            List<String> status,
            List<String> decisionState,
            List<String> matchMethod,
            List<String> vexStatus,
            List<String> vexFreshness,
            List<String> vexProvider,
            Double minConfidence,
            String vulnerabilityId,
            String packageName,
            String ecosystem
    ) {
        Specification<Finding> specification = byFilter(
                tenant,
                severity,
                status,
                decisionState,
                matchMethod,
                vexStatus,
                vexFreshness,
                vexProvider,
                minConfidence,
                vulnerabilityId,
                packageName,
                ecosystem
        );
        return findingRepository.findAll(specification, Sort.by(Sort.Direction.DESC, "updatedAt"));
    }

    public List<Finding> listEntitiesByTenantAndIds(Tenant tenant, List<UUID> findingIds) {
        if (findingIds == null || findingIds.isEmpty()) {
            return List.of();
        }
        return findingRepository.findAllById(findingIds).stream()
                .filter(finding -> finding.getTenant() != null
                        && finding.getTenant().getId() != null
                        && finding.getTenant().getId().equals(tenant.getId()))
                .toList();
    }

    public List<FindingResponse> listByTenant(Tenant tenant) {
        return findingRepository.findByTenantOrderByUpdatedAtDesc(tenant).stream()
                .map(this::toResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public FindingFilterValuesResponse listAvailableFilters(Tenant tenant) {
        LinkedHashSet<String> severities = new LinkedHashSet<>();
        findingRepository.findDistinctSeveritiesByTenant(tenant).stream()
                .filter(this::hasText)
                .map(value -> value.trim().toUpperCase(java.util.Locale.ROOT))
                .forEach(severities::add);
        severities.addAll(List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"));

        LinkedHashSet<String> statuses = new LinkedHashSet<>();
        findingRepository.findDistinctStatusesByTenant(tenant).stream()
                .filter(java.util.Objects::nonNull)
                .map(Enum::name)
                .forEach(statuses::add);
        for (FindingStatus status : FindingStatus.values()) {
            statuses.add(status.name());
        }

        LinkedHashSet<String> decisionStates = new LinkedHashSet<>();
        findingRepository.findDistinctDecisionStatesByTenant(tenant).stream()
                .filter(java.util.Objects::nonNull)
                .map(Enum::name)
                .forEach(decisionStates::add);
        for (FindingDecisionState decisionState : FindingDecisionState.values()) {
            decisionStates.add(decisionState.name());
        }

        LinkedHashSet<String> matchMethods = new LinkedHashSet<>();
        findingRepository.findDistinctMatchMethodsByTenant(tenant).stream()
                .filter(this::hasText)
                .map(value -> value.trim().toLowerCase(java.util.Locale.ROOT))
                .forEach(matchMethods::add);

        LinkedHashSet<String> vexStatuses = new LinkedHashSet<>();
        findingRepository.findDistinctVexStatusesByTenant(tenant).stream()
                .filter(this::hasText)
                .map(value -> value.trim().toUpperCase(java.util.Locale.ROOT))
                .forEach(vexStatuses::add);
        vexStatuses.addAll(List.of("AFFECTED", "NOT_AFFECTED", "FIXED", "NO_PATCH", "UNDER_INVESTIGATION", "UNKNOWN"));

        LinkedHashSet<String> vexFreshness = new LinkedHashSet<>();
        findingRepository.findDistinctVexFreshnessByTenant(tenant).stream()
                .filter(this::hasText)
                .map(value -> value.trim().toUpperCase(java.util.Locale.ROOT))
                .forEach(vexFreshness::add);
        vexFreshness.addAll(List.of("FRESH", "STALE", "UNKNOWN"));

        LinkedHashSet<String> vexProviders = new LinkedHashSet<>();
        findingRepository.findDistinctVexProvidersByTenant(tenant).stream()
                .filter(this::hasText)
                .map(value -> value.trim().toLowerCase(java.util.Locale.ROOT))
                .forEach(vexProviders::add);
        vexProviders.add("unknown");

        return new FindingFilterValuesResponse(
                sortByPreferredOrder(severities, List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN")),
                sortByPreferredOrder(statuses, List.of("OPEN", "RESOLVED", "SUPPRESSED", "AUTO_CLOSED")),
                sortByPreferredOrder(
                        decisionStates,
                        List.of("AFFECTED", "NOT_AFFECTED", "FIXED", "UNDER_INVESTIGATION", "NEEDS_REVIEW")
                ),
                matchMethods.stream().sorted().toList(),
                sortByPreferredOrder(vexStatuses, List.of("AFFECTED", "NOT_AFFECTED", "FIXED", "NO_PATCH", "UNDER_INVESTIGATION", "UNKNOWN")),
                sortByPreferredOrder(vexFreshness, List.of("FRESH", "STALE", "UNKNOWN")),
                vexProviders.stream().sorted().toList()
        );
    }

    public List<FindingResponse> listLatestByTenant(Tenant tenant, int limit) {
        Pageable pageable = PageRequest.of(0, Math.max(1, Math.min(200, limit)), Sort.by(Sort.Direction.DESC, "updatedAt"));
        return findingRepository.findByTenantOrderByUpdatedAtDesc(tenant, pageable).getContent().stream()
                .map(this::toResponse)
                .toList();
    }

    public long countOpen(Tenant tenant) {
        return findingRepository.countByTenantAndStatus(tenant, FindingStatus.OPEN);
    }

    public long countCritical(Tenant tenant) {
        return findingRepository.countByTenantAndStatusAndRiskScoreGreaterThanEqual(tenant, FindingStatus.OPEN, 9.0);
    }

    @Transactional
    public ManualFindingCreationResult createManualFindingsForVulnerability(
            Tenant tenant,
            Vulnerability vulnerability,
            String justification,
            String createdBy,
            Collection<UUID> selectedComponentIds,
            Map<UUID, ApplicabilityState> applicabilityOverrides,
            Map<UUID, AnalystDisposition> analystDispositions
    ) {
        if (tenant == null || tenant.getId() == null || vulnerability == null || vulnerability.getId() == null) {
            return new ManualFindingCreationResult(0, 0, 0, 0);
        }

        RiskPolicy policy = riskPolicyService.getOrCreate(tenant);
        Instant now = Instant.now();
        String normalizedJustification = justification == null ? "" : justification.trim();

        List<ComponentVulnerabilityState> states =
                componentVulnerabilityStateRepository.findByTenant_IdAndVulnerability_Id(tenant.getId(), vulnerability.getId());
        List<Finding> existingFindings =
                findingRepository.findByTenant_IdAndVulnerability_Id(tenant.getId(), vulnerability.getId());
        Map<UUID, Finding> findingsByComponentId = new HashMap<>();
        for (Finding finding : existingFindings) {
            if (finding.getComponent() != null && finding.getComponent().getId() != null) {
                findingsByComponentId.put(finding.getComponent().getId(), finding);
            }
        }

        int eligibleCount = 0;
        int createdCount = 0;
        int reopenedCount = 0;
        int alreadyOpenCount = 0;
        List<Finding> toPersist = new ArrayList<>();
        List<Finding> createdFindings = new ArrayList<>();
        List<Finding> reopenedFindings = new ArrayList<>();

        Set<UUID> selectedIds = selectedComponentIds == null ? Set.of() : selectedComponentIds.stream()
                .filter(Objects::nonNull)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        List<ComponentVulnerabilityState> eligibleStates = states.stream()
                .filter(state -> isEligibleForManualFinding(state, applicabilityOverrides, analystDispositions))
                .filter(state -> state.getComponent() != null && state.getComponent().getId() != null)
                .filter(state -> selectedIds.isEmpty() || selectedIds.contains(state.getComponent().getId()))
                .filter(state -> state.getComponent().getAsset() != null)
                .filter(state -> state.getComponent().getComponentStatus() == InventoryComponentStatus.ACTIVE)
                .sorted(Comparator
                        .comparing((ComponentVulnerabilityState state) -> state.getComponent().getAsset().getName(), Comparator.nullsLast(String::compareToIgnoreCase))
                        .thenComparing(state -> state.getComponent().getPackageName(), Comparator.nullsLast(String::compareToIgnoreCase))
                        .thenComparing(state -> state.getComponent().getVersion(), Comparator.nullsLast(String::compareToIgnoreCase)))
                .toList();

        for (ComponentVulnerabilityState state : eligibleStates) {
            InventoryComponent component = state.getComponent();
            if (component == null || component.getId() == null || component.getAsset() == null) {
                continue;
            }

            eligibleCount++;
            Finding finding = findingsByComponentId.get(component.getId());
            double riskScore = riskScoringService.score(vulnerability, policy, component.getAsset());
            ApplicabilityState effectiveApplicability = effectiveApplicabilityState(state, applicabilityOverrides);
            AnalystDisposition effectiveDisposition = effectiveAnalystDisposition(state, analystDispositions);
            boolean analystOverrideApplied = !state.isEligibleForFinding()
                    && effectiveApplicability == ApplicabilityState.APPLICABLE
                    && effectiveDisposition == AnalystDisposition.IMPACTED;
            String evidence = buildManualFindingEvidence(
                    state,
                    normalizedJustification,
                    createdBy,
                    effectiveApplicability,
                    effectiveDisposition,
                    analystOverrideApplied
            );

            if (finding != null) {
                if (finding.getStatus() == FindingStatus.RESOLVED || finding.getStatus() == FindingStatus.AUTO_CLOSED) {
                    finding.setStatus(FindingStatus.OPEN);
                    finding.setDecisionState(FindingDecisionState.AFFECTED);
                    finding.setMatchedBy(hasText(state.getMatchedBy()) ? state.getMatchedBy() : "manual-org-cve-review");
                    finding.setRiskScore(riskScore);
                    finding.setDueAt(deriveSlaDueAt(finding.getFirstObservedAt(), riskScore, component.getAsset(), policy));
                    finding.setConfidenceScore(state.getConfidenceScore() == null ? 0.0 : state.getConfidenceScore());
                    setEvidenceWithVex(finding, evidence);
                    finding.setPrecedenceTrace(state.getTraceJson());
                    finding.setSuppressionReason(null);
                    finding.setSuppressedUntil(null);
                    finding.setLastObservedAt(now);
                    finding.touch();
                    toPersist.add(finding);
                    reopenedFindings.add(finding);
                    reopenedCount++;
                } else {
                    alreadyOpenCount++;
                }
                continue;
            }

            Finding created = createManualFinding(
                    tenant,
                    component.getAsset(),
                    component,
                    vulnerability,
                    state,
                    riskScore,
                    evidence,
                    now,
                    policy
            );
            toPersist.add(created);
            createdFindings.add(created);
            createdCount++;
        }

        if (!toPersist.isEmpty()) {
            findingRepository.saveAll(toPersist);
            for (Finding finding : createdFindings) {
                findingWorkflowService.appendEvent(
                        finding,
                        "CREATED_BY_MANUAL_CVE_REVIEW",
                        createdBy,
                        "Finding created manually from Org CVE review",
                        Map.of(
                                "justification", normalizedJustification,
                                "matchedBy", finding.getMatchedBy(),
                                "riskScore", finding.getRiskScore(),
                                "analystOverride", Boolean.TRUE.equals(readEvidencePayload(finding.getEvidence()).get("analystOverrideApplied"))
                        )
                );
            }
            for (Finding finding : reopenedFindings) {
                findingWorkflowService.appendEvent(
                        finding,
                        "REOPENED_BY_MANUAL_CVE_REVIEW",
                        createdBy,
                        "Finding reopened manually from Org CVE review",
                        Map.of(
                                "justification", normalizedJustification,
                                "matchedBy", finding.getMatchedBy(),
                                "riskScore", finding.getRiskScore(),
                                "analystOverride", Boolean.TRUE.equals(readEvidencePayload(finding.getEvidence()).get("analystOverrideApplied"))
                        )
                );
            }
        }

        orgCveRecordService.refreshForTenantAndVulnerabilities(tenant, List.of(vulnerability.getId()));
        return new ManualFindingCreationResult(eligibleCount, createdCount, reopenedCount, alreadyOpenCount);
    }

    @Transactional
    public int suppressFindingsForVulnerability(
            Tenant tenant,
            Vulnerability vulnerability,
            String reason,
            String justification,
            String actor,
            Instant suppressedUntil
    ) {
        if (tenant == null || tenant.getId() == null || vulnerability == null || vulnerability.getId() == null) {
            return 0;
        }
        List<Finding> findings = findingRepository.findByTenant_IdAndVulnerability_Id(tenant.getId(), vulnerability.getId());
        if (findings.isEmpty()) {
            return 0;
        }
        return findingWorkflowService.updateWorkflowBulk(
                findings,
                new FindingWorkflowUpdateRequest(
                        FindingStatus.SUPPRESSED.name(),
                        null,
                        null,
                        buildSuppressionReason(reason, justification),
                        suppressedUntil,
                        actor
                )
        );
    }

    private ComponentRecomputeResult recomputeForComponent(
            Tenant tenant,
            InventoryComponent component,
            RiskPolicy policy,
            Instant now,
            CorrelationCandidateService.CandidateBundle candidateBundle,
            List<Finding> prefetchedFindings,
            List<ComponentVulnerabilityState> prefetchedStates
    ) {
        List<Finding> existing = prefetchedFindings == null ? findingRepository.findByComponent(component) : prefetchedFindings;
        List<ComponentVulnerabilityState> existingStates = prefetchedStates == null
                ? componentVulnerabilityStateRepository.findByTenantAndComponent(tenant, component)
                : prefetchedStates;
        Set<UUID> touchedVulnerabilityIds = collectTouchedVulnerabilityIds(existing, existingStates);
        if (component.getAsset() == null
                || component.getAsset().getState() != AssetState.ACTIVE
                || component.getComponentStatus() != InventoryComponentStatus.ACTIVE) {
            resolveInactiveComponentAssessments(existingStates, now);
            resolveInactiveComponentFindings(existing, now);
            return new ComponentRecomputeResult(0, touchedVulnerabilityIds);
        }

        CorrelationCandidateService.CandidateBundle bundle = candidateBundle == null
                ? correlationCandidateService.buildCandidateBundle(List.of(component))
                : candidateBundle;
        List<CorrelationCandidateService.CandidateMatch> candidates = correlationCandidateService.candidatesForComponent(component, bundle);
        Map<UUID, List<PrecedenceResolverService.CandidateDecision>> decisionsByVulnerability =
                buildCandidateDecisionsByVulnerability(component, candidates, policy);

        Map<UUID, Finding> existingByVulnerability = new HashMap<>();
        for (Finding finding : existing) {
            if (finding.getVulnerability() != null && finding.getVulnerability().getId() != null) {
                existingByVulnerability.put(finding.getVulnerability().getId(), finding);
            }
        }
        Map<UUID, ComponentVulnerabilityState> existingStateByVulnerability = new HashMap<>();
        for (ComponentVulnerabilityState state : existingStates) {
            if (state.getVulnerability() != null && state.getVulnerability().getId() != null) {
                existingStateByVulnerability.put(state.getVulnerability().getId(), state);
            }
        }
        touchedVulnerabilityIds.addAll(existingByVulnerability.keySet());
        touchedVulnerabilityIds.addAll(existingStateByVulnerability.keySet());
        touchedVulnerabilityIds.addAll(decisionsByVulnerability.keySet());

        Set<UUID> activeVulnerabilityIds = new HashSet<>();
        Set<UUID> evaluatedVulnerabilityIds = new HashSet<>();
        List<Finding> toPersist = new ArrayList<>();
        List<Finding> createdFindings = new ArrayList<>();
        List<ComponentVulnerabilityState> stateRowsToPersist = new ArrayList<>();
        List<UUID> sortedVulnerabilityIds = new ArrayList<>(decisionsByVulnerability.keySet());
        sortedVulnerabilityIds.sort(UUID::compareTo);

        for (UUID vulnerabilityId : sortedVulnerabilityIds) {
            List<PrecedenceResolverService.CandidateDecision> decisions = decisionsByVulnerability.get(vulnerabilityId);
            if (decisions == null || decisions.isEmpty()) {
                continue;
            }
            evaluatedVulnerabilityIds.add(vulnerabilityId);

            PrecedenceResolverService.PrecedenceResolution resolution = precedenceResolverService.resolve(decisions);
            PrecedenceResolverService.CandidateDecision selected = resolution.primary();
            if (selected == null || selected.target() == null || selected.target().getVulnerability() == null) {
                continue;
            }
            Vulnerability vulnerability = selected.target().getVulnerability();
            if (vulnerability.getId() == null) {
                continue;
            }

            ImpactEvaluationService.VexOverlayOutcome vexOverlay =
                    resolveVexOverlay(component, vulnerabilityId, null, candidates, policy);
            ImpactEvaluationService.ImpactAssessment impactAssessment =
                    impactEvaluationService.evaluate(resolution, selected, vexOverlay);
            upsertComponentVulnerabilityState(
                    tenant,
                    component,
                    vulnerability,
                    selected,
                    resolution,
                    vexOverlay,
                    impactAssessment,
                    now,
                    existingStateByVulnerability,
                    stateRowsToPersist
            );
            if (!impactAssessment.findingEligible()) {
                continue;
            }

            Finding finding = existingByVulnerability.get(vulnerability.getId());
            PrecedenceResolverService.CandidateDecision findingSelected = selected;
            if (finding == null) {
                findingSelected = selectAutomaticFindingCandidate(resolution, decisions);
                if (findingSelected == null) {
                    continue;
                }
            }

            RiskScoringService.RiskScoreOutcome riskScoreOutcome =
                    riskScoringService.score(vulnerability, policy, component.getAsset(), findingSelected, resolution);
            double riskScore = riskScoreOutcome.score();
            VulnerabilityTarget target = findingSelected.target();
            String evidence = findingEvidenceService.buildEvidence(
                    component,
                    vulnerability,
                    target,
                    findingSelected,
                    resolution,
                    riskScoreOutcome
            );
            evidence = withVexOverlayEvidence(evidence, vexOverlay);

            boolean findingCreated = false;
            if (finding == null) {
                if (!isAutomaticFindingGenerationEnabled(policy)) {
                    continue;
                }
                finding = createFinding(
                        tenant,
                        component.getAsset(),
                        component,
                        vulnerability,
                        findingSelected,
                        resolution,
                        riskScore,
                        evidence,
                        now,
                        policy
                );
                existingByVulnerability.put(vulnerability.getId(), finding);
                createdFindings.add(finding);
                findingCreated = true;
            }
            activeVulnerabilityIds.add(vulnerability.getId());

            boolean findingChanged = findingCreated;
            if (!findingCreated && finding.getStatus() == FindingStatus.RESOLVED) {
                finding.setStatus(FindingStatus.OPEN);
                findingChanged = true;
            }

            FindingDecisionState nextDecisionState = impactAssessment.findingDecisionState();
            if (!findingCreated && finding.getDecisionState() != nextDecisionState) {
                findingChanged = true;
            }
            String nextMatchedBy = findingSelected.matchedBy();
            if (!findingCreated && !java.util.Objects.equals(finding.getMatchedBy(), nextMatchedBy)) {
                findingChanged = true;
            }
            if (!findingCreated && Double.compare(finding.getRiskScore(), riskScore) != 0) {
                findingChanged = true;
            }
            Instant nextDueAt = deriveSlaDueAt(finding.getFirstObservedAt(), riskScore, component.getAsset(), policy);
            if (!findingCreated && !java.util.Objects.equals(finding.getDueAt(), nextDueAt)) {
                findingChanged = true;
            }
            if (!findingCreated && Double.compare(finding.getConfidenceScore(), findingSelected.confidence()) != 0) {
                findingChanged = true;
            }
            String nextPrecedenceTrace = toJson(resolution.precedenceTrace());
            if (!findingCreated && !java.util.Objects.equals(finding.getEvidence(), evidence)) {
                findingChanged = true;
            }
            if (!findingCreated && !java.util.Objects.equals(finding.getPrecedenceTrace(), nextPrecedenceTrace)) {
                findingChanged = true;
            }

            if (findingChanged) {
                finding.setDecisionState(nextDecisionState);
                finding.setMatchedBy(nextMatchedBy);
                finding.setRiskScore(riskScore);
                finding.setDueAt(nextDueAt);
                finding.setConfidenceScore(findingSelected.confidence());
                setEvidenceWithVex(finding, evidence);
                finding.setPrecedenceTrace(nextPrecedenceTrace);
                finding.setLastObservedAt(now);
                finding.touch();
                toPersist.add(finding);
            }
        }

        for (Finding finding : existing) {
            UUID vulnerabilityId = finding.getVulnerability() == null ? null : finding.getVulnerability().getId();
            if (vulnerabilityId != null
                    && !activeVulnerabilityIds.contains(vulnerabilityId)
                    && finding.getStatus() != FindingStatus.RESOLVED
                    && finding.getStatus() != FindingStatus.AUTO_CLOSED) {
                finding.setStatus(FindingStatus.RESOLVED);
                finding.setDecisionState(FindingDecisionState.NOT_AFFECTED);
                finding.setSuppressionReason(null);
                finding.setSuppressedUntil(null);
                finding.touch();
                toPersist.add(finding);
            }
        }

        for (ComponentVulnerabilityState state : existingStateByVulnerability.values()) {
            if (state.getVulnerability() == null || state.getVulnerability().getId() == null) {
                continue;
            }
            UUID vulnerabilityId = state.getVulnerability().getId();
            if (evaluatedVulnerabilityIds.contains(vulnerabilityId)) {
                continue;
            }
            if (state.getApplicabilityState() == ApplicabilityState.NOT_APPLICABLE
                    && state.getImpactState() == ImpactState.NOT_IMPACTED) {
                continue;
            }
            state.setApplicabilityState(ApplicabilityState.NOT_APPLICABLE);
            state.setApplicabilityReason("component_not_observed");
            state.setImpactState(ImpactState.NOT_IMPACTED);
            state.setImpactReason("component_not_observed");
            state.setVexStatus("UNKNOWN");
            state.setVexProvider("unknown");
            state.setVexFreshness("UNKNOWN");
            state.setVexSource(null);
            state.setVexTargetId(null);
            state.setMatchedVexAssertionId(null);
            state.setMatchedBy("not-observed");
            state.setSelectedTargetSource(null);
            state.setPrecedenceReason("component_not_observed");
            state.setConfidenceScore(0.0);
            state.setEligibleForFinding(false);
            state.setTraceJson("{\"reason\":\"component_not_observed\"}");
            state.setLastEvaluatedAt(now);
            state.setStateChangedAt(now);
            state.touch();
            stateRowsToPersist.add(state);
        }

        if (!stateRowsToPersist.isEmpty()) {
            componentVulnerabilityStateRepository.saveAll(stateRowsToPersist);
        }

        if (!toPersist.isEmpty()) {
            findingRepository.saveAll(toPersist);
            for (Finding finding : createdFindings) {
                findingWorkflowService.appendEvent(
                        finding,
                        "CREATED_BY_CORRELATION",
                        "system",
                        "Finding created from deterministic inventory-to-vulnerability correlation",
                        Map.of(
                                "matchedBy", finding.getMatchedBy(),
                                "riskScore", finding.getRiskScore(),
                                "confidenceScore", finding.getConfidenceScore()
                        )
                );
            }
        }
        return new ComponentRecomputeResult(activeVulnerabilityIds.size(), touchedVulnerabilityIds);
    }

    private int resolveInactiveComponentFindings(List<Finding> existing, Instant now) {
        if (existing.isEmpty()) {
            return 0;
        }
        List<Finding> toPersist = new ArrayList<>();
        for (Finding finding : existing) {
            if (finding.getStatus() == FindingStatus.RESOLVED || finding.getStatus() == FindingStatus.AUTO_CLOSED) {
                continue;
            }
            finding.setStatus(FindingStatus.RESOLVED);
            finding.setDecisionState(FindingDecisionState.NOT_AFFECTED);
            finding.setSuppressionReason(null);
            finding.setSuppressedUntil(null);
            finding.setLastObservedAt(now);
            finding.touch();
            toPersist.add(finding);
        }
        if (!toPersist.isEmpty()) {
            findingRepository.saveAll(toPersist);
        }
        return 0;
    }

    private void resolveInactiveComponentAssessments(List<ComponentVulnerabilityState> existingStates, Instant now) {
        if (existingStates == null || existingStates.isEmpty()) {
            return;
        }
        List<ComponentVulnerabilityState> toPersist = new ArrayList<>();
        for (ComponentVulnerabilityState state : existingStates) {
            if (state.getApplicabilityState() == ApplicabilityState.NOT_APPLICABLE
                    && state.getImpactState() == ImpactState.NOT_IMPACTED) {
                continue;
            }
            state.setApplicabilityState(ApplicabilityState.NOT_APPLICABLE);
            state.setApplicabilityReason("component_inactive");
            state.setImpactState(ImpactState.NOT_IMPACTED);
            state.setImpactReason("component_inactive");
            state.setVexStatus("UNKNOWN");
            state.setVexProvider("unknown");
            state.setVexFreshness("UNKNOWN");
            state.setVexSource(null);
            state.setVexTargetId(null);
            state.setMatchedVexAssertionId(null);
            state.setMatchedBy("component-inactive");
            state.setSelectedTargetSource(null);
            state.setPrecedenceReason("component_inactive");
            state.setConfidenceScore(0.0);
            state.setEligibleForFinding(false);
            state.setTraceJson("{\"reason\":\"component_inactive\"}");
            state.setLastEvaluatedAt(now);
            state.setStateChangedAt(now);
            state.touch();
            toPersist.add(state);
        }
        if (!toPersist.isEmpty()) {
            componentVulnerabilityStateRepository.saveAll(toPersist);
        }
    }

    private Set<UUID> collectTouchedVulnerabilityIds(
            List<Finding> existingFindings,
            List<ComponentVulnerabilityState> existingStates
    ) {
        Set<UUID> vulnerabilityIds = new LinkedHashSet<>();
        if (existingFindings != null) {
            for (Finding finding : existingFindings) {
                UUID vulnerabilityId = finding.getVulnerability() == null ? null : finding.getVulnerability().getId();
                if (vulnerabilityId != null) {
                    vulnerabilityIds.add(vulnerabilityId);
                }
            }
        }
        if (existingStates != null) {
            for (ComponentVulnerabilityState state : existingStates) {
                UUID vulnerabilityId = state.getVulnerability() == null ? null : state.getVulnerability().getId();
                if (vulnerabilityId != null) {
                    vulnerabilityIds.add(vulnerabilityId);
                }
            }
        }
        return vulnerabilityIds;
    }

    private record ComponentRecomputeResult(
            int activeFindingCount,
            Set<UUID> touchedVulnerabilityIds
    ) {
    }

    private String exposureKey(UUID componentId, UUID vulnerabilityId) {
        return componentId + "::" + vulnerabilityId;
    }

    private Specification<Finding> byTenant(Tenant tenant) {
        return (root, query, cb) -> cb.equal(root.get("tenant"), tenant);
    }

    private Specification<Finding> byFilter(
            Tenant tenant,
            List<String> severity,
            List<String> status,
            List<String> decisionState,
            List<String> matchMethod,
            List<String> vexStatus,
            List<String> vexFreshness,
            List<String> vexProvider,
            Double minConfidence,
            String vulnerabilityId,
            String packageName,
            String ecosystem
    ) {
        return byTenant(tenant)
                .and(bySeverity(severity))
                .and(byStatus(status))
                .and(byDecisionState(decisionState))
                .and(byMatchMethod(matchMethod))
                .and(byVexStatus(vexStatus))
                .and(byVexFreshness(vexFreshness))
                .and(byVexProvider(vexProvider))
                .and(byMinConfidence(minConfidence))
                .and(byVulnerabilityId(vulnerabilityId))
                .and(byPackageName(packageName))
                .and(byEcosystem(ecosystem));
    }

    private Specification<Finding> bySeverity(List<String> severities) {
        Set<String> normalized = normalizeFilterValues(severities);
        if (normalized.isEmpty()) {
            return null;
        }
        Set<String> upper = normalized.stream().map(String::toUpperCase).collect(java.util.stream.Collectors.toSet());
        return (root, query, cb) -> cb.upper(root.join("vulnerability").get("severity")).in(upper);
    }

    private Specification<Finding> byStatus(List<String> statuses) {
        Set<String> normalized = normalizeFilterValues(statuses);
        if (normalized.isEmpty()) {
            return null;
        }
        Set<FindingStatus> findingStatuses = new HashSet<>();
        for (String value : normalized) {
            try {
                findingStatuses.add(FindingStatus.valueOf(value.toUpperCase()));
            } catch (IllegalArgumentException ignored) {
                // Ignore unknown status values and proceed with valid tokens.
            }
        }
        if (findingStatuses.isEmpty()) {
            return null;
        }
        return (root, query, cb) -> root.get("status").in(findingStatuses);
    }

    private Specification<Finding> byDecisionState(List<String> decisionStates) {
        Set<String> normalized = normalizeFilterValues(decisionStates);
        if (normalized.isEmpty()) {
            return null;
        }
        Set<FindingDecisionState> states = new HashSet<>();
        for (String value : normalized) {
            try {
                states.add(FindingDecisionState.valueOf(value.toUpperCase()));
            } catch (IllegalArgumentException ignored) {
                // Ignore unknown values and continue with valid tokens.
            }
        }
        if (states.isEmpty()) {
            return null;
        }
        return (root, query, cb) -> root.get("decisionState").in(states);
    }

    private Specification<Finding> byMatchMethod(List<String> matchMethods) {
        Set<String> normalized = normalizeFilterValues(matchMethods);
        if (normalized.isEmpty()) {
            return null;
        }
        Set<String> lower = normalized.stream().map(String::toLowerCase).collect(java.util.stream.Collectors.toSet());
        return (root, query, cb) -> cb.lower(root.get("matchedBy")).in(lower);
    }

    private Specification<Finding> byVexStatus(List<String> vexStatuses) {
        Set<String> normalized = normalizeUpperFilterValues(vexStatuses);
        if (normalized.isEmpty()) {
            return null;
        }
        return (root, query, cb) -> {
            List<jakarta.persistence.criteria.Predicate> predicates = new ArrayList<>();
            if (normalized.contains("UNKNOWN")) {
                predicates.add(cb.isNull(root.get("vexStatus")));
            }
            predicates.add(cb.upper(root.get("vexStatus")).in(normalized));
            return cb.or(predicates.toArray(new jakarta.persistence.criteria.Predicate[0]));
        };
    }

    private Specification<Finding> byVexFreshness(List<String> vexFreshness) {
        Set<String> normalized = normalizeUpperFilterValues(vexFreshness);
        if (normalized.isEmpty()) {
            return null;
        }
        return (root, query, cb) -> {
            List<jakarta.persistence.criteria.Predicate> predicates = new ArrayList<>();
            if (normalized.contains("UNKNOWN")) {
                predicates.add(cb.isNull(root.get("vexFreshness")));
            }
            predicates.add(cb.upper(root.get("vexFreshness")).in(normalized));
            return cb.or(predicates.toArray(new jakarta.persistence.criteria.Predicate[0]));
        };
    }

    private Specification<Finding> byVexProvider(List<String> vexProviders) {
        Set<String> normalized = normalizeLowerFilterValues(vexProviders);
        if (normalized.isEmpty()) {
            return null;
        }
        return (root, query, cb) -> {
            List<jakarta.persistence.criteria.Predicate> predicates = new ArrayList<>();
            if (normalized.contains("unknown")) {
                predicates.add(cb.isNull(root.get("vexProvider")));
            }
            predicates.add(cb.lower(root.get("vexProvider")).in(normalized));
            return cb.or(predicates.toArray(new jakarta.persistence.criteria.Predicate[0]));
        };
    }

    private List<Finding> applyVexFilters(
            List<Finding> findings,
            Set<String> vexStatuses,
            Set<String> vexFreshness,
            Set<String> vexProviders
    ) {
        if ((vexStatuses == null || vexStatuses.isEmpty())
                && (vexFreshness == null || vexFreshness.isEmpty())
                && (vexProviders == null || vexProviders.isEmpty())) {
            return findings;
        }

        List<Finding> filtered = new ArrayList<>();
        for (Finding finding : findings) {
            VexFilterEvidence vex = parseVexFilterEvidence(finding);
            if (vexStatuses != null && !vexStatuses.isEmpty() && !vexStatuses.contains(vex.status())) {
                continue;
            }
            if (vexFreshness != null && !vexFreshness.isEmpty() && !vexFreshness.contains(vex.freshness())) {
                continue;
            }
            if (vexProviders != null && !vexProviders.isEmpty() && !vexProviders.contains(vex.provider())) {
                continue;
            }
            filtered.add(finding);
        }
        return filtered;
    }

    private void setEvidenceWithVex(Finding finding, String evidence) {
        finding.setEvidence(evidence);
        VexFilterEvidence vex = parseVexFilterEvidence(finding);
        finding.setVexStatus(vex.status());
        finding.setVexFreshness(vex.freshness());
        finding.setVexProvider(vex.provider());
        finding.setMatchedVexAssertionId(parseVexAssertionId(finding.getEvidence()));
    }

    private VexFilterEvidence parseVexFilterEvidence(Finding finding) {
        if (finding == null || !hasText(finding.getEvidence())) {
            return new VexFilterEvidence("UNKNOWN", "UNKNOWN", "unknown");
        }
        try {
            JsonNode root = objectMapper.readTree(finding.getEvidence());
            JsonNode overlay = root.path("vexOverlay");
            String overlayStatus = impactEvaluationService.normalizeStatus(overlay.path("status").asText(""));
            String overlayFreshness = impactEvaluationService.normalizeFreshness(overlay.path("freshness").asText(""));
            String overlayProvider = impactEvaluationService.normalizeProvider(overlay.path("provider").asText(""));
            if (!"UNKNOWN".equals(overlayStatus) || !"UNKNOWN".equals(overlayFreshness) || !"unknown".equals(overlayProvider)) {
                return new VexFilterEvidence(overlayStatus, overlayFreshness, overlayProvider);
            }
            JsonNode trace = root.path("applicabilityTrace");
            String status = impactEvaluationService.normalizeStatus(traceValue(trace, "vexStatus"));
            String freshness = impactEvaluationService.normalizeFreshness(traceValue(trace, "vexFreshnessOutcome"));
            String provider = impactEvaluationService.normalizeProvider(traceValue(trace, "vexProvider"));
            return new VexFilterEvidence(status, freshness, provider);
        } catch (Exception ignored) {
            return new VexFilterEvidence("UNKNOWN", "UNKNOWN", "unknown");
        }
    }

    private UUID parseVexAssertionId(String evidence) {
        if (!hasText(evidence)) {
            return null;
        }
        try {
            JsonNode root = objectMapper.readTree(evidence);
            String value = root.path("vexOverlay").path("assertionId").asText("");
            return hasText(value) ? UUID.fromString(value.trim()) : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    private String traceValue(JsonNode trace, String key) {
        if (trace == null || trace.isMissingNode() || trace.isNull() || key == null) {
            return null;
        }
        String direct = trace.path(key).asText("");
        if (hasText(direct)) {
            return direct.trim();
        }
        JsonNode base = trace.path("baseApplicability");
        String nested = base.path(key).asText("");
        if (hasText(nested)) {
            return nested.trim();
        }
        return null;
    }

    private ImpactEvaluationService.VexOverlayOutcome resolveVexOverlay(
            InventoryComponent component,
            UUID vulnerabilityId,
            String sourceKey
    ) {
        return resolveVexOverlay(component, vulnerabilityId, sourceKey, null, null);
    }

    private ImpactEvaluationService.VexOverlayOutcome resolveVexOverlay(
            InventoryComponent component,
            UUID vulnerabilityId,
            String sourceKey,
            List<CorrelationCandidateService.CandidateMatch> candidateMatches,
            RiskPolicy policy
    ) {
        if (component == null || component.getId() == null || vulnerabilityId == null) {
            return ImpactEvaluationService.VexOverlayOutcome.none();
        }

        List<CorrelationCandidateService.CandidateMatch> resolvedCandidates = candidateMatches == null
                ? correlationCandidateService.candidatesForComponent(
                component,
                correlationCandidateService.buildCandidateBundle(List.of(component)))
                : candidateMatches;
        return vexAssertionMatchService.resolve(component, vulnerabilityId, sourceKey, resolvedCandidates, policy);
    }

    private String withVexOverlayEvidence(String evidence, ImpactEvaluationService.VexOverlayOutcome overlay) {
        if (overlay == null || !overlay.applied()) {
            return evidence;
        }
        Map<String, Object> payload = readEvidencePayload(evidence);
        Map<String, Object> overlayPayload = new LinkedHashMap<>();
        overlayPayload.put("state", overlay.finalState().name());
        overlayPayload.put("status", overlay.status());
        overlayPayload.put("provider", overlay.provider());
        overlayPayload.put("freshness", overlay.freshness());
        overlayPayload.put("reason", overlay.reason());
        overlayPayload.put("source", overlay.source());
        overlayPayload.put("assertionId", overlay.assertionId());
        overlayPayload.put("targetId", overlay.targetId());
        overlayPayload.put("targetUpdatedAt", overlay.targetUpdatedAt() == null ? null : overlay.targetUpdatedAt().toString());
        payload.put("vexOverlay", overlayPayload);
        return toJson(payload);
    }

    private Map<String, Object> readEvidencePayload(String evidence) {
        if (!hasText(evidence)) {
            return new LinkedHashMap<>();
        }
        try {
            JsonNode node = objectMapper.readTree(evidence);
            return objectMapper.convertValue(node, new com.fasterxml.jackson.core.type.TypeReference<>() {
            });
        } catch (Exception ignored) {
            return new LinkedHashMap<>();
        }
    }

    private String traceString(Map<String, Object> trace, String key) {
        if (trace == null || trace.isEmpty() || key == null || key.isBlank()) {
            return null;
        }
        Object value = trace.get(key);
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value).trim();
        return text.isEmpty() ? null : text;
    }

    private Set<String> normalizeUpperFilterValues(List<String> rawValues) {
        return normalizeFilterValues(rawValues).stream()
                .map(value -> value.trim().toUpperCase(Locale.ROOT))
                .collect(java.util.stream.Collectors.toSet());
    }

    private Set<String> normalizeLowerFilterValues(List<String> rawValues) {
        return normalizeFilterValues(rawValues).stream()
                .map(value -> value.trim().toLowerCase(Locale.ROOT))
                .collect(java.util.stream.Collectors.toSet());
    }

    private Set<String> normalizeFilterValues(List<String> rawValues) {
        if (rawValues == null || rawValues.isEmpty()) {
            return Set.of();
        }
        Set<String> values = new HashSet<>();
        for (String rawValue : rawValues) {
            if (rawValue == null || rawValue.isBlank()) {
                continue;
            }
            String[] splitValues = rawValue.split(",");
            for (String splitValue : splitValues) {
                String normalized = splitValue == null ? "" : splitValue.trim();
                if (normalized.isEmpty() || "ALL".equalsIgnoreCase(normalized)) {
                    continue;
                }
                values.add(normalized);
            }
        }
        return values;
    }

    private record VexFilterEvidence(
            String status,
            String freshness,
            String provider
    ) {
    }

    public record ManualFindingCreationResult(
            int eligibleComponentCount,
            int createdCount,
            int reopenedCount,
            int alreadyOpenCount
    ) {
    }

    private void upsertComponentVulnerabilityState(
            Tenant tenant,
            InventoryComponent component,
            Vulnerability vulnerability,
            PrecedenceResolverService.CandidateDecision selected,
            PrecedenceResolverService.PrecedenceResolution resolution,
            ImpactEvaluationService.VexOverlayOutcome vexOverlay,
            ImpactEvaluationService.ImpactAssessment impactAssessment,
            Instant now,
            Map<UUID, ComponentVulnerabilityState> existingStateByVulnerability,
            List<ComponentVulnerabilityState> stateRowsToPersist
    ) {
        if (tenant == null || component == null || vulnerability == null || vulnerability.getId() == null) {
            return;
        }

        ComponentVulnerabilityState state = existingStateByVulnerability.get(vulnerability.getId());
        boolean created = false;
        if (state == null) {
            state = new ComponentVulnerabilityState();
            state.setTenant(tenant);
            state.setComponent(component);
            state.setVulnerability(vulnerability);
            created = true;
        }

        String newVexStatus = vexOverlay == null ? "UNKNOWN" : defaultString(vexOverlay.status(), "UNKNOWN");
        String newVexProvider = vexOverlay == null ? "unknown" : defaultString(vexOverlay.provider(), "unknown");
        String newVexFreshness = vexOverlay == null ? "UNKNOWN" : defaultString(vexOverlay.freshness(), "UNKNOWN");
        String newVexSource = vexOverlay == null ? null : vexOverlay.source();
        UUID newMatchedVexAssertionId = vexOverlay == null ? null : vexOverlay.assertionId();
        String newSelectedTargetSource = selected == null || selected.target() == null
                ? null
                : selected.target().getSource();

        boolean stateChanged = created
                || state.getApplicabilityState() != impactAssessment.applicabilityState()
                || state.getImpactState() != impactAssessment.impactState()
                || !java.util.Objects.equals(state.getApplicabilityReason(), impactAssessment.applicabilityReason())
                || !java.util.Objects.equals(state.getVexStatus(), newVexStatus)
                || !java.util.Objects.equals(state.getVexProvider(), newVexProvider)
                || !java.util.Objects.equals(state.getVexFreshness(), newVexFreshness)
                || !java.util.Objects.equals(state.getVexSource(), newVexSource)
                || !java.util.Objects.equals(state.getMatchedVexAssertionId(), newMatchedVexAssertionId)
                || !java.util.Objects.equals(state.getImpactReason(), impactAssessment.impactReason())
                || !java.util.Objects.equals(state.getPrecedenceReason(), resolution == null ? "unknown" : resolution.reason())
                || !java.util.Objects.equals(state.getMatchedBy(), selected == null ? null : selected.matchedBy())
                || !java.util.Objects.equals(state.getSelectedTargetSource(), newSelectedTargetSource)
                || !java.util.Objects.equals(state.getConfidenceScore(), selected == null ? null : selected.confidence())
                || !java.util.Objects.equals(state.getApplicabilityReasonDetail(), impactAssessment.applicabilityReasonDetail())
                || !java.util.Objects.equals(state.getImpactReasonDetail(), impactAssessment.impactReasonDetail());
        if (!stateChanged) {
            return;
        }

        state.setApplicabilityState(impactAssessment.applicabilityState());
        state.setApplicabilityReason(impactAssessment.applicabilityReason());
        state.setApplicabilityReasonDetail(impactAssessment.applicabilityReasonDetail());
        state.setImpactState(impactAssessment.impactState());
        state.setImpactReason(impactAssessment.impactReason());
        state.setImpactReasonDetail(impactAssessment.impactReasonDetail());
        state.setVexStatus(newVexStatus);
        state.setVexProvider(newVexProvider);
        state.setVexFreshness(newVexFreshness);
        state.setVexSource(newVexSource);
        state.setMatchedVexAssertionId(newMatchedVexAssertionId);
        state.setVexTargetId(vexOverlay == null ? null : vexOverlay.targetId());
        state.setPrecedenceReason(resolution == null ? "unknown" : resolution.reason());
        state.setMatchedBy(selected == null ? null : selected.matchedBy());
        state.setSelectedTargetSource(newSelectedTargetSource);
        state.setConfidenceScore(selected == null ? null : selected.confidence());
        state.setEligibleForFinding(impactAssessment.findingEligible());
        state.setLastEvaluatedAt(now);
        state.setStateChangedAt(now);
        state.setTraceJson(toJson(buildStateTrace(selected, resolution, vexOverlay, impactAssessment)));
        state.touch();
        existingStateByVulnerability.put(vulnerability.getId(), state);
        stateRowsToPersist.add(state);
    }

    private Map<String, Object> buildStateTrace(
            PrecedenceResolverService.CandidateDecision selected,
            PrecedenceResolverService.PrecedenceResolution resolution,
            ImpactEvaluationService.VexOverlayOutcome vexOverlay,
            ImpactEvaluationService.ImpactAssessment impactAssessment
    ) {
        Map<String, Object> trace = new LinkedHashMap<>();
        trace.put("matchedBy", selected == null ? null : selected.matchedBy());
        trace.put("selectedTargetSource", selected == null || selected.target() == null ? null : selected.target().getSource());
        trace.put("confidence", selected == null ? null : selected.confidence());
        trace.put("precedenceReason", resolution == null ? null : resolution.reason());
        trace.put("applicabilityState", impactAssessment.applicabilityState().name());
        trace.put("applicabilityReason", impactAssessment.applicabilityReason());
        trace.put("applicabilityReasonDetail", impactAssessment.applicabilityReasonDetail());
        trace.put("impactState", impactAssessment.impactState().name());
        trace.put("impactReason", impactAssessment.impactReason());
        trace.put("impactReasonDetail", impactAssessment.impactReasonDetail());
        if (vexOverlay != null) {
            trace.put("vexStatus", vexOverlay.status());
            trace.put("vexProvider", vexOverlay.provider());
            trace.put("vexFreshness", vexOverlay.freshness());
            trace.put("vexSource", vexOverlay.source());
            trace.put("vexAssertionId", vexOverlay.assertionId());
            trace.put("vexTargetId", vexOverlay.targetId());
            trace.put("vexReason", vexOverlay.reason());
        }
        return trace;
    }

    private String defaultString(String value, String fallback) {
        return hasText(value) ? value : fallback;
    }

    private List<String> sortByPreferredOrder(Set<String> values, List<String> preferredOrder) {
        Set<String> remaining = new java.util.LinkedHashSet<>(values);
        List<String> sorted = new ArrayList<>();
        for (String preferredValue : preferredOrder) {
            if (remaining.remove(preferredValue)) {
                sorted.add(preferredValue);
            }
        }
        sorted.addAll(remaining.stream().sorted().toList());
        return sorted;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private Specification<Finding> byMinConfidence(Double minConfidence) {
        if (minConfidence == null) {
            return null;
        }
        return (root, query, cb) -> cb.greaterThanOrEqualTo(root.get("confidenceScore"), minConfidence);
    }

    private Specification<Finding> byVulnerabilityId(String vulnerabilityId) {
        if (vulnerabilityId == null || vulnerabilityId.isBlank()) {
            return null;
        }
        String expected = vulnerabilityId.trim().toUpperCase();
        return (root, query, cb) -> cb.equal(
                cb.upper(root.join("vulnerability").get("externalId")),
                expected);
    }

    private Specification<Finding> byPackageName(String packageName) {
        if (packageName == null || packageName.isBlank()) {
            return null;
        }
        String expected = packageName.trim().toLowerCase();
        return (root, query, cb) -> cb.equal(
                cb.lower(root.join("component").get("packageName")),
                expected);
    }

    private Specification<Finding> byEcosystem(String ecosystem) {
        if (ecosystem == null || ecosystem.isBlank()) {
            return null;
        }
        String expected = ecosystem.trim().toLowerCase();
        return (root, query, cb) -> cb.equal(
                cb.lower(root.join("component").get("ecosystem")),
                expected);
    }

    public FindingResponse toResponse(Finding finding) {
        Vulnerability vulnerability = finding.getVulnerability();
        InventoryComponent component = finding.getComponent();
        Map<String, Object> evidencePayload = readEvidencePayload(finding.getEvidence());

        return new FindingResponse(
                finding.getId(),
                finding.getAsset().getName(),
                finding.getAsset().getType().name(),
                component.getPackageName(),
                component.getVersion(),
                vulnerability.getExternalId(),
                vulnerability.getSource().name(),
                vulnerability.getSeverity(),
                vulnerability.isInKev(),
                vulnerability.getEpssScore(),
                finding.getRiskScore(),
                finding.getConfidenceScore(),
                finding.getMatchedBy(),
                finding.getAssignedTo(),
                finding.getDueAt(),
                finding.getSuppressionReason(),
                finding.getSuppressedUntil(),
                finding.getEvidence(),
                finding.getPrecedenceTrace(),
                finding.getVexStatus(),
                finding.getVexProvider(),
                finding.getVexFreshness(),
                finding.getMatchedVexAssertionId(),
                traceString(evidencePayload, "impactReason"),
                finding.getFirstObservedAt(),
                finding.getLastObservedAt(),
                finding.getDecisionState(),
                finding.getStatus(),
                finding.getUpdatedAt(),
                component.getEolSlug(),
                component.getEolCycle(),
                component.getEolDate(),
                component.getIsEol(),
                component.getEolDate() != null
                        ? (int) java.time.temporal.ChronoUnit.DAYS.between(java.time.LocalDate.now(), component.getEolDate())
                        : null);
    }

    private Map<UUID, List<VulnerabilityConfigExpr>> nvdExpressionsByVulnerability(
            List<CorrelationCandidateService.CandidateMatch> candidates
    ) {
        Set<Vulnerability> vulnerabilities = candidates.stream()
                .map(CorrelationCandidateService.CandidateMatch::target)
                .filter(target -> target.getSource() != null && target.getSource().toLowerCase(java.util.Locale.ROOT).contains("nvd"))
                .map(VulnerabilityTarget::getVulnerability)
                .collect(java.util.stream.Collectors.toSet());
        if (vulnerabilities.isEmpty()) {
            return Map.of();
        }
        List<VulnerabilityConfigExpr> rows = vulnerabilityConfigExprRepository.findByVulnerabilityInAndSource(vulnerabilities, "nvd");
        Map<UUID, List<VulnerabilityConfigExpr>> grouped = new HashMap<>();
        for (VulnerabilityConfigExpr row : rows) {
            if (row.getVulnerability() == null || row.getVulnerability().getId() == null) {
                continue;
            }
            grouped.computeIfAbsent(row.getVulnerability().getId(), ignored -> new ArrayList<>()).add(row);
        }
        return grouped;
    }

    private Map<UUID, List<PrecedenceResolverService.CandidateDecision>> buildCandidateDecisionsByVulnerability(
            InventoryComponent component,
            List<CorrelationCandidateService.CandidateMatch> candidates,
            RiskPolicy policy
    ) {
        Map<UUID, List<PrecedenceResolverService.CandidateDecision>> candidateDecisionsByVulnerability = new HashMap<>();
        Map<UUID, List<VulnerabilityConfigExpr>> nvdTreeByVulnerability = nvdExpressionsByVulnerability(candidates);
        for (CorrelationCandidateService.CandidateMatch candidate : candidates) {
            VulnerabilityTarget target = candidate.target();
            UUID vulnerabilityId = target.getVulnerability().getId();
            ApplicabilityDecisionService.ApplicabilityDecision applicabilityDecision =
                    applicabilityDecisionService.evaluateCorrelation(component, target, policy);
            applicabilityDecision = applyNvdConfigurationDecision(
                    component,
                    target,
                    applicabilityDecision,
                    nvdTreeByVulnerability.getOrDefault(vulnerabilityId, List.of())
            );
            Map<String, Double> confidenceBreakdown = new LinkedHashMap<>(candidate.confidenceBreakdown());
            double confidence = applyApplicabilityPenalty(confidenceBreakdown, candidate.confidence(), applicabilityDecision);
            PrecedenceResolverService.CandidateDecision decision = new PrecedenceResolverService.CandidateDecision(
                    target,
                    candidate.matchedBy(),
                    candidate.rank(),
                    confidence,
                    confidenceBreakdown,
                    applicabilityDecision
            );
            candidateDecisionsByVulnerability
                    .computeIfAbsent(vulnerabilityId, ignored -> new ArrayList<>())
                    .add(decision);
        }
        return candidateDecisionsByVulnerability;
    }

    private String categorizeNotApplicableReason(String applicabilityReason, String precedenceReason, String source) {
        String reason = applicabilityReason == null ? "" : applicabilityReason.trim().toLowerCase(java.util.Locale.ROOT);
        String precedence = precedenceReason == null ? "" : precedenceReason.trim().toLowerCase(java.util.Locale.ROOT);
        String normalizedSource = source == null ? "" : source.trim().toLowerCase(java.util.Locale.ROOT);

        if (reason.contains("stale_or_untrusted")) {
            return "VEX Stale Or Untrusted";
        }
        if (reason.contains("vex_not_affected")) {
            return "VEX Not Affected";
        }
        if (reason.contains("vex_fixed")) {
            return "VEX Fixed";
        }
        if (reason.contains("nvd_config_override_not_affected")) {
            return "NVD Configuration Not Affected";
        }
        if (reason.contains("exact_version_mismatch")
                || reason.contains("below_introduced")
                || reason.contains("at_or_above_fixed")
                || reason.contains("below_start")
                || reason.contains("above_end")
                || reason.contains("mismatch")) {
            return "Version Outside Affected Range";
        }
        if (precedence.contains("highest_precedence_not_affected")
                && (normalizedSource.contains("csaf")
                || normalizedSource.contains("advisory")
                || normalizedSource.contains("ghsa"))) {
            return "Vendor Advisory Not Affected";
        }
        return "Correlation Not Affected";
    }

    public record NotApplicableProjection(
            long neverOpenedNotApplicable,
            long deferredUnderInvestigation,
            Map<String, Long> categories
    ) {
    }

    private ApplicabilityDecisionService.ApplicabilityDecision applyNvdConfigurationDecision(
            InventoryComponent component,
            VulnerabilityTarget target,
            ApplicabilityDecisionService.ApplicabilityDecision current,
            List<VulnerabilityConfigExpr> nvdExpressions
    ) {
        if (target.getSource() == null || !target.getSource().toLowerCase(java.util.Locale.ROOT).contains("nvd")) {
            return current;
        }

        ApplicabilityDecisionService.ApplicabilityDecision treeDecision = nvdConfigurationDecisionService.evaluate(component, nvdExpressions);
        Map<String, Object> mergedTrace = new LinkedHashMap<>();
        mergedTrace.put("baseApplicability", current.trace());
        mergedTrace.put("nvdConfiguration", treeDecision.trace());

        if (treeDecision.result() == ApplicabilityDecisionService.ApplicabilityResult.FALSE) {
            return new ApplicabilityDecisionService.ApplicabilityDecision(
                    ApplicabilityDecisionService.ApplicabilityResult.FALSE,
                    "nvd_config_override_not_affected",
                    mergedTrace
            );
        }
        if (current.result() == ApplicabilityDecisionService.ApplicabilityResult.FALSE) {
            return current;
        }
        if (treeDecision.result() == ApplicabilityDecisionService.ApplicabilityResult.UNKNOWN) {
            return new ApplicabilityDecisionService.ApplicabilityDecision(
                    ApplicabilityDecisionService.ApplicabilityResult.UNKNOWN,
                    "nvd_config_unknown",
                    mergedTrace
            );
        }
        return new ApplicabilityDecisionService.ApplicabilityDecision(
                current.result(),
                current.reason(),
                mergedTrace
        );
    }

    private double applyApplicabilityPenalty(
            Map<String, Double> confidenceBreakdown,
            double currentConfidence,
            ApplicabilityDecisionService.ApplicabilityDecision applicabilityDecision
    ) {
        double penalty = 0.0;
        if (applicabilityDecision.result() == ApplicabilityDecisionService.ApplicabilityResult.UNKNOWN
                && applicabilityDecision.reason() != null
                && (applicabilityDecision.reason().contains("compare_error")
                || applicabilityDecision.reason().contains("nvd_config_unknown"))) {
            penalty = 0.12;
        }
        confidenceBreakdown.put("applicabilityPenalty", penalty);
        return Math.max(0.05, Math.min(0.99, currentConfidence - penalty));
    }

    private String toJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) {
            return "{}";
        }
    }

    private Finding createFinding(
            Tenant tenant,
            Asset asset,
            InventoryComponent component,
            Vulnerability vulnerability,
            PrecedenceResolverService.CandidateDecision selected,
            PrecedenceResolverService.PrecedenceResolution resolution,
            double riskScore,
            String evidence,
            Instant now,
            RiskPolicy policy
    ) {
        Finding finding = new Finding();
        finding.setTenant(tenant);
        finding.setAsset(asset);
        finding.setComponent(component);
        finding.setVulnerability(vulnerability);
        finding.setStatus(FindingStatus.OPEN);
        finding.setDecisionState(FindingDecisionState.AFFECTED);
        finding.setMatchedBy(selected.matchedBy());
        finding.setRiskScore(riskScore);
        finding.setConfidenceScore(selected.confidence());
        finding.setFirstObservedAt(now);
        finding.setLastObservedAt(now);
        finding.setDueAt(deriveSlaDueAt(now, riskScore, asset, policy));
        finding.setSuppressionReason(null);
        finding.setSuppressedUntil(null);
        setEvidenceWithVex(finding, evidence);
        finding.setPrecedenceTrace(toJson(resolution.precedenceTrace()));
        finding.touch();
        return finding;
    }

    private Finding createManualFinding(
            Tenant tenant,
            Asset asset,
            InventoryComponent component,
            Vulnerability vulnerability,
            ComponentVulnerabilityState state,
            double riskScore,
            String evidence,
            Instant now,
            RiskPolicy policy
    ) {
        Finding finding = new Finding();
        finding.setTenant(tenant);
        finding.setAsset(asset);
        finding.setComponent(component);
        finding.setVulnerability(vulnerability);
        finding.setStatus(FindingStatus.OPEN);
        finding.setDecisionState(FindingDecisionState.AFFECTED);
        finding.setMatchedBy(hasText(state.getMatchedBy()) ? state.getMatchedBy() : "manual-org-cve-review");
        finding.setRiskScore(riskScore);
        finding.setConfidenceScore(state.getConfidenceScore() == null ? 0.0 : state.getConfidenceScore());
        finding.setFirstObservedAt(now);
        finding.setLastObservedAt(now);
        finding.setDueAt(deriveSlaDueAt(now, riskScore, asset, policy));
        finding.setSuppressionReason(null);
        finding.setSuppressedUntil(null);
        setEvidenceWithVex(finding, evidence);
        finding.setPrecedenceTrace(state.getTraceJson());
        finding.touch();
        return finding;
    }

    private boolean isCpeMatchMethod(String matchedBy) {
        if (!hasText(matchedBy)) {
            return false;
        }
        return matchedBy.trim().toLowerCase(java.util.Locale.ROOT).startsWith("cpe-");
    }

    private boolean isFindingCreationEligible(PrecedenceResolverService.CandidateDecision decision) {
        if (decision == null || !hasText(decision.matchedBy())) {
            return false;
        }
        return isFindingCreationEligible(decision.matchedBy(), decision.confidence());
    }

    private boolean isFindingCreationEligible(String matchedBy, Double confidenceScore) {
        if (!hasText(matchedBy)) {
            return false;
        }
        if (isCpeMatchMethod(matchedBy)) {
            return true;
        }
        if (!isSupportedNonCpeMatch(matchedBy)) {
            return false;
        }
        return (confidenceScore == null ? 0.0 : confidenceScore) >= nonCpeCreateMinConfidence;
    }

    private boolean isEligibleForManualFinding(
            ComponentVulnerabilityState state,
            Map<UUID, ApplicabilityState> applicabilityOverrides,
            Map<UUID, AnalystDisposition> analystDispositions
    ) {
        if (state == null) {
            return false;
        }
        if (state.isEligibleForFinding()) {
            return true;
        }
        ApplicabilityState effectiveApplicability = effectiveApplicabilityState(state, applicabilityOverrides);
        AnalystDisposition effectiveDisposition = effectiveAnalystDisposition(state, analystDispositions);
        return effectiveApplicability == ApplicabilityState.APPLICABLE
                && effectiveDisposition == AnalystDisposition.IMPACTED;
    }

    private ApplicabilityState effectiveApplicabilityState(
            ComponentVulnerabilityState state,
            Map<UUID, ApplicabilityState> applicabilityOverrides
    ) {
        if (state == null || state.getComponent() == null || state.getComponent().getId() == null) {
            return ApplicabilityState.UNKNOWN;
        }
        if (applicabilityOverrides == null || applicabilityOverrides.isEmpty()) {
            return state.getApplicabilityState();
        }
        return applicabilityOverrides.getOrDefault(state.getComponent().getId(), state.getApplicabilityState());
    }

    private AnalystDisposition effectiveAnalystDisposition(
            ComponentVulnerabilityState state,
            Map<UUID, AnalystDisposition> analystDispositions
    ) {
        if (state == null || state.getComponent() == null || state.getComponent().getId() == null) {
            return AnalystDisposition.UNKNOWN;
        }
        if (analystDispositions == null || analystDispositions.isEmpty()) {
            return state.getAnalystDisposition();
        }
        return analystDispositions.getOrDefault(state.getComponent().getId(), state.getAnalystDisposition());
    }

    private boolean isSupportedNonCpeMatch(String matchedBy) {
        String normalized = matchedBy == null ? "" : matchedBy.trim().toLowerCase(java.util.Locale.ROOT);
        return normalized.startsWith("identity-")
                || normalized.startsWith("purl-")
                || normalized.startsWith("coord-")
                || normalized.startsWith("advisory-pkg-");
    }

    private boolean isAutomaticFindingGenerationEnabled(RiskPolicy policy) {
        return policy != null && policy.getFindingGenerationMode() == RiskPolicy.FindingGenerationMode.AUTO;
    }

    private PrecedenceResolverService.CandidateDecision selectAutomaticFindingCandidate(
            PrecedenceResolverService.PrecedenceResolution resolution,
            List<PrecedenceResolverService.CandidateDecision> decisions
    ) {
        if (resolution == null || decisions == null || decisions.isEmpty()) {
            return null;
        }
        PrecedenceResolverService.CandidateDecision primary = resolution.primary();
        if (primary == null
                || primary.target() == null
                || primary.applicabilityDecision() == null
                || !primary.applicabilityDecision().isAffected()) {
            return null;
        }
        if (isFindingCreationEligible(primary)) {
            return primary;
        }

        int sourcePriority = precedenceResolverService.sourcePriority(primary.target().getSource());
        return decisions.stream()
                .filter(Objects::nonNull)
                .filter(candidate -> candidate.target() != null)
                .filter(candidate -> candidate.applicabilityDecision() != null && candidate.applicabilityDecision().isAffected())
                .filter(this::isFindingCreationEligible)
                .filter(candidate -> precedenceResolverService.sourcePriority(candidate.target().getSource()) == sourcePriority)
                .sorted(Comparator
                        .comparingInt(PrecedenceResolverService.CandidateDecision::rank)
                        .thenComparing(Comparator.comparingDouble(PrecedenceResolverService.CandidateDecision::confidence).reversed())
                        .thenComparing(candidate -> candidate.target().getId(), Comparator.nullsLast(Comparator.naturalOrder())))
                .findFirst()
                .orElse(null);
    }

    private String buildManualFindingEvidence(
            ComponentVulnerabilityState state,
            String justification,
            String createdBy,
            ApplicabilityState effectiveApplicability,
            AnalystDisposition effectiveDisposition,
            boolean analystOverrideApplied
    ) {
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("source", "manual-org-cve-review");
        evidence.put("analyst", createdBy);
        evidence.put("justification", justification);
        evidence.put("matchedBy", state.getMatchedBy());
        evidence.put("confidenceScore", state.getConfidenceScore());
        evidence.put("applicabilityState", state.getApplicabilityState() == null ? null : state.getApplicabilityState().name());
        evidence.put("impactState", state.getImpactState() == null ? null : state.getImpactState().name());
        evidence.put("impactReason", state.getImpactReason());
        evidence.put("effectiveApplicabilityState", effectiveApplicability == null ? null : effectiveApplicability.name());
        evidence.put("effectiveAnalystDisposition", effectiveDisposition == null ? null : effectiveDisposition.name());
        evidence.put("analystOverrideApplied", analystOverrideApplied);
        evidence.put("lastEvaluatedAt", state.getLastEvaluatedAt());
        if (hasText(state.getTraceJson())) {
            evidence.put("correlationTrace", state.getTraceJson());
        }
        return toJson(evidence);
    }

    private boolean isSuppressionExpired(Finding finding, Instant now) {
        return finding.getStatus() == FindingStatus.SUPPRESSED
                && finding.getSuppressedUntil() != null
                && finding.getSuppressedUntil().isBefore(now);
    }

    private String buildSuppressionReason(String reason, String justification) {
        String normalizedReason = hasText(reason) ? reason.trim() : "UNSPECIFIED";
        String normalizedJustification = hasText(justification) ? justification.trim() : null;
        if (normalizedJustification == null) {
            return normalizedReason;
        }
        return normalizedReason + ": " + normalizedJustification;
    }

    private Instant deriveSlaDueAt(Instant firstObservedAt, double riskScore, Asset asset, RiskPolicy policy) {
        if (firstObservedAt == null) {
            return null;
        }
        int baseSlaDays = baseSlaDaysForRisk(riskScore, policy);
        if (baseSlaDays <= 0) {
            return null;
        }
        double multiplier = slaMultiplierForAsset(asset, policy);
        int effectiveDays = (int) Math.max(1, Math.round(baseSlaDays * multiplier));
        return firstObservedAt.plus(Duration.ofDays(effectiveDays));
    }

    private int baseSlaDaysForRisk(double riskScore, RiskPolicy policy) {
        if (riskScore >= policy.getCriticalThreshold()) {
            return policy.getCriticalSlaDays();
        }
        if (riskScore >= policy.getHighThreshold()) {
            return policy.getHighSlaDays();
        }
        if (riskScore >= 4.0) {
            return policy.getMediumSlaDays();
        }
        return policy.getLowSlaDays();
    }

    private double slaMultiplierForAsset(Asset asset, RiskPolicy policy) {
        BusinessCriticality criticality = asset == null || asset.getBusinessCriticality() == null
                ? BusinessCriticality.MEDIUM
                : asset.getBusinessCriticality();
        return switch (criticality) {
            case CRITICAL -> policy.getAssetCriticalSlaMultiplier();
            case HIGH -> policy.getAssetHighSlaMultiplier();
            case MEDIUM -> policy.getAssetMediumSlaMultiplier();
            case LOW -> policy.getAssetLowSlaMultiplier();
        };
    }

}
