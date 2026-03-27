package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.AnalystDisposition;
import com.prototype.vulnwatch.domain.ApplicabilityState;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.ComponentVulnerabilityState;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.dto.FindingWorkflowUpdateRequest;
import com.prototype.vulnwatch.repo.ComponentVulnerabilityStateRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class FindingWorkflowFacade {

    private final FindingRepository findingRepository;
    private final ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository;
    private final RiskPolicyService riskPolicyService;
    private final RiskScoringService riskScoringService;
    private final FindingWorkflowService findingWorkflowService;
    private final OrgCveRecordService orgCveRecordService;
    private final FindingSlaService findingSlaService;
    private final ObjectMapper objectMapper;

    public FindingWorkflowFacade(
            FindingRepository findingRepository,
            ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository,
            RiskPolicyService riskPolicyService,
            RiskScoringService riskScoringService,
            FindingWorkflowService findingWorkflowService,
            OrgCveRecordService orgCveRecordService,
            FindingSlaService findingSlaService,
            ObjectMapper objectMapper
    ) {
        this.findingRepository = findingRepository;
        this.componentVulnerabilityStateRepository = componentVulnerabilityStateRepository;
        this.riskPolicyService = riskPolicyService;
        this.riskScoringService = riskScoringService;
        this.findingWorkflowService = findingWorkflowService;
        this.orgCveRecordService = orgCveRecordService;
        this.findingSlaService = findingSlaService;
        this.objectMapper = objectMapper;
    }

    @Transactional
    public ManualFindingCreationResult createManualFindingsForVulnerability(
            Tenant tenant,
            Vulnerability vulnerability,
            String justification,
            String userId,
            Collection<UUID> componentIds,
            Map<UUID, ApplicabilityState> applicabilityDecisions,
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
        Map<UUID, Finding> findingsByComponentId = new LinkedHashMap<>();
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

        Set<UUID> selectedIds = componentIds == null ? Set.of() : componentIds.stream()
                .filter(Objects::nonNull)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        List<ComponentVulnerabilityState> eligibleStates = states.stream()
                .filter(state -> isEligibleForManualFinding(state, applicabilityDecisions, analystDispositions))
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
            ApplicabilityState effectiveApplicability = effectiveApplicabilityState(state, applicabilityDecisions);
            AnalystDisposition effectiveDisposition = effectiveAnalystDisposition(state, analystDispositions);
            boolean analystOverrideApplied = !state.isEligibleForFinding()
                    && effectiveApplicability == ApplicabilityState.APPLICABLE
                    && effectiveDisposition == AnalystDisposition.IMPACTED;
            String evidence = buildManualFindingEvidence(
                    state,
                    normalizedJustification,
                    userId,
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
                    finding.setDueAt(findingSlaService.deriveDueAt(finding.getFirstObservedAt(), riskScore, component.getAsset(), policy));
                    finding.setConfidenceScore(state.getConfidenceScore() == null ? 0.0 : state.getConfidenceScore());
                    applyManualEvidence(finding, evidence);
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
                        userId,
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
                        userId,
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
            String userId,
            Instant expiresAt
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
                        expiresAt,
                        userId
                )
        );
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
        finding.setDueAt(findingSlaService.deriveDueAt(now, riskScore, asset, policy));
        finding.setSuppressionReason(null);
        finding.setSuppressedUntil(null);
        applyManualEvidence(finding, evidence);
        finding.setPrecedenceTrace(state.getTraceJson());
        finding.touch();
        return finding;
    }

    private void applyManualEvidence(Finding finding, String evidence) {
        finding.setEvidence(evidence);
        finding.setVexStatus("UNKNOWN");
        finding.setVexFreshness("UNKNOWN");
        finding.setVexProvider("unknown");
        finding.setMatchedVexAssertionId(null);
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

    private String buildSuppressionReason(String reason, String justification) {
        String normalizedReason = hasText(reason) ? reason.trim() : "UNSPECIFIED";
        String normalizedJustification = hasText(justification) ? justification.trim() : null;
        if (normalizedJustification == null) {
            return normalizedReason;
        }
        return normalizedReason + ": " + normalizedJustification;
    }

    private Map<String, Object> readEvidencePayload(String evidence) {
        if (!hasText(evidence)) {
            return new LinkedHashMap<>();
        }
        try {
            JsonNode node = objectMapper.readTree(evidence);
            return objectMapper.convertValue(node, new TypeReference<Map<String, Object>>() {
            });
        } catch (Exception ignored) {
            return new LinkedHashMap<>();
        }
    }

    private String toJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception ignored) {
            return "{}";
        }
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
