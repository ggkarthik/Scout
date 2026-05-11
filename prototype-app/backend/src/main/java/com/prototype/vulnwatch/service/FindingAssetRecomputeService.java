package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetState;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class FindingAssetRecomputeService {

    private static final Logger LOG = LoggerFactory.getLogger(FindingAssetRecomputeService.class);

    private final FindingRepository findingRepository;
    private final InventoryComponentRepository inventoryComponentRepository;
    private final CorrelationCandidateService correlationCandidateService;
    private final RiskPolicyService riskPolicyService;
    private final FindingsScoreService findingsScoreService;
    private final FindingWorkflowService findingWorkflowService;
    private final ImpactEvaluationService impactEvaluationService;
    private final FindingEvidenceService findingEvidenceService;
    private final PrecedenceResolverService precedenceResolverService;
    private final OrgCveRecordService orgCveRecordService;
    private final FindingSlaService findingSlaService;
    private final FindingCorrelationAnalysisService findingCorrelationAnalysisService;
    private final FindingCorrelationMutationService findingCorrelationMutationService;

    public FindingAssetRecomputeService(
            FindingRepository findingRepository,
            InventoryComponentRepository inventoryComponentRepository,
            CorrelationCandidateService correlationCandidateService,
            RiskPolicyService riskPolicyService,
            FindingsScoreService findingsScoreService,
            FindingWorkflowService findingWorkflowService,
            ImpactEvaluationService impactEvaluationService,
            FindingEvidenceService findingEvidenceService,
            PrecedenceResolverService precedenceResolverService,
            OrgCveRecordService orgCveRecordService,
            FindingSlaService findingSlaService,
            FindingCorrelationAnalysisService findingCorrelationAnalysisService,
            FindingCorrelationMutationService findingCorrelationMutationService
    ) {
        this.findingRepository = findingRepository;
        this.inventoryComponentRepository = inventoryComponentRepository;
        this.correlationCandidateService = correlationCandidateService;
        this.riskPolicyService = riskPolicyService;
        this.findingsScoreService = findingsScoreService;
        this.findingWorkflowService = findingWorkflowService;
        this.impactEvaluationService = impactEvaluationService;
        this.findingEvidenceService = findingEvidenceService;
        this.precedenceResolverService = precedenceResolverService;
        this.orgCveRecordService = orgCveRecordService;
        this.findingSlaService = findingSlaService;
        this.findingCorrelationAnalysisService = findingCorrelationAnalysisService;
        this.findingCorrelationMutationService = findingCorrelationMutationService;
    }

    @Transactional
    public int recomputeForAsset(Tenant tenant, Asset asset) {
        List<InventoryComponent> components = inventoryComponentRepository.findByAssetAndComponentStatus(
                asset,
                InventoryComponentStatus.ACTIVE
        );
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
                            )
                    );
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
                    findingCorrelationAnalysisService.buildCandidateDecisionsByVulnerability(component, candidates, policy);

            List<UUID> vulnerabilityIds = new ArrayList<>(candidateDecisionsByVulnerability.keySet());
            vulnerabilityIds.sort(UUID::compareTo);
            for (UUID vulnerabilityId : vulnerabilityIds) {
                List<PrecedenceResolverService.CandidateDecision> decisions =
                        candidateDecisionsByVulnerability.get(vulnerabilityId);
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
                        findingCorrelationMutationService.resolveVexOverlay(component, vulnerabilityId, null, candidates, policy);
                ImpactEvaluationService.ImpactAssessment impactAssessment =
                        impactEvaluationService.evaluate(resolution, resolution.primary(), vexOverlay);
                if (resolution.finalState() != PrecedenceResolverService.FinalState.AFFECTED
                        || resolution.primary() == null
                        || resolution.primary().applicabilityDecision() == null
                        || !resolution.primary().applicabilityDecision().isAffected()) {
                    continue;
                }
                if (!impactAssessment.findingEligible()) {
                    PrecedenceResolverService.CandidateDecision selected = resolution.primary();
                    VulnerabilityTarget target = selected.target();
                    Vulnerability vulnerability = target.getVulnerability();
                    String key = exposureKey(component.getId(), vulnerability.getId());
                    Finding existingFinding = existingByKey.get(key);

                    if (existingFinding != null
                            && existingFinding.getStatus() != FindingStatus.RESOLVED
                            && existingFinding.getStatus() != FindingStatus.AUTO_CLOSED) {
                        existingFinding.setStatus(FindingStatus.RESOLVED);
                        existingFinding.setDecisionState(impactAssessment.findingDecisionState());
                        findingCorrelationMutationService.setEvidenceWithVex(
                                existingFinding,
                                findingCorrelationMutationService.withVexOverlayEvidence(existingFinding.getEvidence(), vexOverlay)
                        );
                        existingFinding.setLastObservedAt(now);
                        existingFinding.touch();

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
                                        "previousDecisionState",
                                        existingFinding.getDecisionState() != null
                                                ? existingFinding.getDecisionState().name()
                                                : "UNKNOWN",
                                        "vexSource", vexOverlay.source() != null ? vexOverlay.source() : "unknown",
                                        "resolvedAt", now.toString()
                                )
                        );

                        LOG.info(
                                "Resolved finding {} for component {} and vulnerability {} using canonical impact state {}",
                                existingFinding.getId(),
                                component.getId(),
                                vulnerability.getExternalId(),
                                impactAssessment.impactState()
                        );
                    }
                    continue;
                }

                PrecedenceResolverService.CandidateDecision selected = resolution.primary();
                String key = exposureKey(component.getId(), vulnerabilityId);
                Finding finding = existingByKey.get(key);
                PrecedenceResolverService.CandidateDecision findingSelected = selected;
                if (finding == null) {
                    findingSelected = findingCorrelationAnalysisService.selectAutomaticFindingCandidate(resolution, decisions);
                    if (findingSelected == null) {
                        continue;
                    }
                }
                VulnerabilityTarget target = findingSelected.target();
                Vulnerability vulnerability = target.getVulnerability();
                if (finding == null && orgCveRecordService.isActivelySuppressed(tenant, vulnerability, now)) {
                    continue;
                }

                String existingSeverityOverride = finding != null ? finding.getSeverityOverride() : null;
                double riskScore = findingsScoreService.computeFromParts(
                        policy.getFindingsScoreConfig(), vulnerability, asset, component, existingSeverityOverride);
                String evidence = findingEvidenceService.buildEvidence(
                        component,
                        vulnerability,
                        target,
                        findingSelected,
                        resolution,
                        null
                );
                evidence = findingCorrelationMutationService.withVexOverlayEvidence(evidence, vexOverlay);

                if (finding == null) {
                    if (!isAutomaticFindingGenerationEnabled(policy)) {
                        continue;
                    }
                    finding = findingCorrelationMutationService.createFinding(
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
                                Map.of("reopenedAt", now)
                        );
                    }
                }
                finding.setDecisionState(impactAssessment.findingDecisionState());
                finding.setMatchedBy(findingSelected.matchedBy());
                finding.setRiskScore(riskScore);
                finding.setDueAt(findingSlaService.deriveDueAt(finding.getFirstObservedAt(), riskScore, asset, policy));
                finding.setConfidenceScore(findingSelected.confidence());
                findingCorrelationMutationService.setEvidenceWithVex(finding, evidence);
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
                        )
                );
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
                precedenceReasonCounts
        );
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

    private String exposureKey(UUID componentId, UUID vulnerabilityId) {
        return componentId + "::" + vulnerabilityId;
    }

    private String toJson(Object value) {
        try {
            return new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(value);
        } catch (Exception e) {
            return "{}";
        }
    }

    private boolean isAutomaticFindingGenerationEnabled(RiskPolicy policy) {
        return policy != null && policy.getFindingGenerationMode() == RiskPolicy.FindingGenerationMode.AUTO;
    }

    private boolean isSuppressionExpired(Finding finding, Instant now) {
        return finding.getStatus() == FindingStatus.SUPPRESSED
                && finding.getSuppressedUntil() != null
                && finding.getSuppressedUntil().isBefore(now);
    }
}
