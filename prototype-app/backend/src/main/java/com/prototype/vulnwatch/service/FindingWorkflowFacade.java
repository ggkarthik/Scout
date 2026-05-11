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
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
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
    private final InventoryComponentRepository inventoryComponentRepository;
    private final RiskPolicyService riskPolicyService;
    private final FindingsScoreService findingsScoreService;
    private final FindingWorkflowService findingWorkflowService;
    private final OrgCveRecordService orgCveRecordService;
    private final FindingSlaService findingSlaService;
    private final ObjectMapper objectMapper;

    public FindingWorkflowFacade(
            FindingRepository findingRepository,
            ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository,
            InventoryComponentRepository inventoryComponentRepository,
            RiskPolicyService riskPolicyService,
            FindingsScoreService findingsScoreService,
            FindingWorkflowService findingWorkflowService,
            OrgCveRecordService orgCveRecordService,
            FindingSlaService findingSlaService,
            ObjectMapper objectMapper
    ) {
        this.findingRepository = findingRepository;
        this.componentVulnerabilityStateRepository = componentVulnerabilityStateRepository;
        this.inventoryComponentRepository = inventoryComponentRepository;
        this.riskPolicyService = riskPolicyService;
        this.findingsScoreService = findingsScoreService;
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
        return createManualFindingsForVulnerability(tenant, vulnerability, justification, userId, componentIds, applicabilityDecisions, analystDispositions, null, null);
    }

    @Transactional
    public ManualFindingCreationResult createManualFindingsForVulnerability(
            Tenant tenant,
            Vulnerability vulnerability,
            String justification,
            String userId,
            Collection<UUID> componentIds,
            Map<UUID, ApplicabilityState> applicabilityDecisions,
            Map<UUID, AnalystDisposition> analystDispositions,
            String severityOverride,
            Instant dueDateOverride
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
            String existingSeverityOverride = finding != null ? finding.getSeverityOverride() : severityOverride;
            double riskScore = findingsScoreService.computeFromParts(
                    policy.getFindingsScoreConfig(), vulnerability, component.getAsset(), component, existingSeverityOverride);
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
                    finding.setDueAt(dueDateOverride != null ? dueDateOverride : findingSlaService.deriveDueAt(finding.getFirstObservedAt(), riskScore, component.getAsset(), policy));
                    if (severityOverride != null && !severityOverride.isBlank()) {
                        finding.setSeverityOverride(severityOverride.toUpperCase());
                    }
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
                    policy,
                    severityOverride,
                    dueDateOverride
            );
            toPersist.add(created);
            createdFindings.add(created);
            createdCount++;
        }

        // Phase 2: handle selected component IDs that have no ComponentVulnerabilityState for this
        // CVE (investigation-identified software added manually). If the analyst explicitly marked
        // them APPLICABLE + IMPACTED we create findings directly from the InventoryComponent.
        if (!selectedIds.isEmpty() && applicabilityDecisions != null && analystDispositions != null) {
            Set<UUID> coveredByState = states.stream()
                    .filter(s -> s.getComponent() != null && s.getComponent().getId() != null)
                    .map(s -> s.getComponent().getId())
                    .collect(Collectors.toSet());
            List<UUID> uncorrelatedIds = selectedIds.stream()
                    .filter(id -> !coveredByState.contains(id))
                    .filter(id -> applicabilityDecisions.get(id) == ApplicabilityState.APPLICABLE
                            && analystDispositions.get(id) == AnalystDisposition.IMPACTED)
                    .collect(Collectors.toList());
            if (!uncorrelatedIds.isEmpty()) {
                List<InventoryComponent> uncorrelatedComponents = inventoryComponentRepository.findAllById(uncorrelatedIds);
                for (InventoryComponent component : uncorrelatedComponents) {
                    if (component.getAsset() == null || component.getComponentStatus() != InventoryComponentStatus.ACTIVE) {
                        continue;
                    }
                    eligibleCount++;
                    Finding existing = findingsByComponentId.get(component.getId());
                    double riskScore = findingsScoreService.computeFromParts(
                            policy.getFindingsScoreConfig(), vulnerability, component.getAsset(), component,
                            existing != null ? existing.getSeverityOverride() : severityOverride);
                    String evidence = buildUncorrelatedFindingEvidence(normalizedJustification, userId);
                    if (existing != null) {
                        if (existing.getStatus() == FindingStatus.RESOLVED || existing.getStatus() == FindingStatus.AUTO_CLOSED) {
                            existing.setStatus(FindingStatus.OPEN);
                            existing.setDecisionState(FindingDecisionState.AFFECTED);
                            existing.setMatchedBy("manual-org-cve-review");
                            existing.setRiskScore(riskScore);
                            existing.setDueAt(dueDateOverride != null ? dueDateOverride : findingSlaService.deriveDueAt(existing.getFirstObservedAt(), riskScore, component.getAsset(), policy));
                            if (severityOverride != null && !severityOverride.isBlank()) {
                                existing.setSeverityOverride(severityOverride.toUpperCase());
                            }
                            existing.setConfidenceScore(0.0);
                            applyManualEvidence(existing, evidence);
                            existing.setSuppressionReason(null);
                            existing.setSuppressedUntil(null);
                            existing.setLastObservedAt(now);
                            existing.touch();
                            toPersist.add(existing);
                            reopenedFindings.add(existing);
                            reopenedCount++;
                        } else {
                            alreadyOpenCount++;
                        }
                    } else {
                        Finding created = new Finding();
                        created.setTenant(tenant);
                        created.setAsset(component.getAsset());
                        created.setComponent(component);
                        created.setVulnerability(vulnerability);
                        created.setStatus(FindingStatus.OPEN);
                        created.setDecisionState(FindingDecisionState.AFFECTED);
                        created.setMatchedBy("manual-org-cve-review");
                        created.setRiskScore(riskScore);
                        created.setConfidenceScore(0.0);
                        created.setFirstObservedAt(now);
                        created.setLastObservedAt(now);
                        created.setDueAt(dueDateOverride != null ? dueDateOverride : findingSlaService.deriveDueAt(now, riskScore, component.getAsset(), policy));
                        if (severityOverride != null && !severityOverride.isBlank()) {
                            created.setSeverityOverride(severityOverride.toUpperCase());
                        }
                        created.setSuppressionReason(null);
                        created.setSuppressedUntil(null);
                        applyManualEvidence(created, evidence);
                        created.touch();
                        toPersist.add(created);
                        createdFindings.add(created);
                        createdCount++;
                    }
                }
            }
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

    /**
     * CVE_FIX mode: creates ONE finding for the entire CVE, using the first eligible component
     * as the representative. All other affected assets are embedded in the finding's evidence JSON.
     */
    @Transactional
    public ManualFindingCreationResult createCveFixGroupedFinding(
            Tenant tenant,
            Vulnerability vulnerability,
            String justification,
            String userId,
            Collection<UUID> componentIds,
            Map<UUID, ApplicabilityState> applicabilityDecisions,
            Map<UUID, AnalystDisposition> analystDispositions,
            String severityOverride,
            Instant dueDateOverride,
            boolean forceNew
    ) {
        if (tenant == null || tenant.getId() == null || vulnerability == null || vulnerability.getId() == null) {
            return new ManualFindingCreationResult(0, 0, 0, 0);
        }

        RiskPolicy policy = riskPolicyService.getOrCreate(tenant);
        Instant now = Instant.now();
        String normalizedJustification = justification == null ? "" : justification.trim();

        Set<UUID> selectedIds = componentIds == null ? Set.of() : componentIds.stream()
                .filter(Objects::nonNull)
                .collect(Collectors.toCollection(LinkedHashSet::new));

        List<ComponentVulnerabilityState> allStates =
                componentVulnerabilityStateRepository.findByTenant_IdAndVulnerability_Id(tenant.getId(), vulnerability.getId());

        List<ComponentVulnerabilityState> eligibleStates = allStates.stream()
                .filter(state -> isEligibleForManualFinding(state, applicabilityDecisions, analystDispositions))
                .filter(state -> state.getComponent() != null && state.getComponent().getId() != null)
                .filter(state -> selectedIds.isEmpty() || selectedIds.contains(state.getComponent().getId()))
                .filter(state -> state.getComponent().getAsset() != null)
                .filter(state -> state.getComponent().getComponentStatus() == InventoryComponentStatus.ACTIVE)
                .toList();

        // Phase 2: investigation-identified components that have no ComponentVulnerabilityState but
        // were explicitly marked APPLICABLE + IMPACTED by the analyst.
        List<InventoryComponent> uncorrelatedComponents = List.of();
        if (!selectedIds.isEmpty() && applicabilityDecisions != null && analystDispositions != null) {
            Set<UUID> coveredByState = allStates.stream()
                    .filter(s -> s.getComponent() != null && s.getComponent().getId() != null)
                    .map(s -> s.getComponent().getId())
                    .collect(Collectors.toSet());
            List<UUID> uncorrelatedIds = selectedIds.stream()
                    .filter(id -> !coveredByState.contains(id))
                    .filter(id -> applicabilityDecisions.get(id) == ApplicabilityState.APPLICABLE
                            && analystDispositions.get(id) == AnalystDisposition.IMPACTED)
                    .collect(Collectors.toList());
            if (!uncorrelatedIds.isEmpty()) {
                uncorrelatedComponents = inventoryComponentRepository.findAllById(uncorrelatedIds).stream()
                        .filter(c -> c.getAsset() != null && c.getComponentStatus() == InventoryComponentStatus.ACTIVE)
                        .collect(Collectors.toList());
            }
        }

        if (eligibleStates.isEmpty() && uncorrelatedComponents.isEmpty()) {
            return new ManualFindingCreationResult(0, 0, 0, 0);
        }

        int totalEligible = eligibleStates.size() + uncorrelatedComponents.size();

        // Build the list of all affected asset summaries for the evidence JSON (Phase 1 + Phase 2)
        List<Map<String, Object>> affectedAssets = new ArrayList<>();
        for (ComponentVulnerabilityState state : eligibleStates) {
            InventoryComponent comp = state.getComponent();
            Map<String, Object> entry = buildAffectedAssetEntry(comp);
            affectedAssets.add(entry);
        }
        for (InventoryComponent comp : uncorrelatedComponents) {
            Map<String, Object> entry = buildAffectedAssetEntry(comp);
            affectedAssets.add(entry);
        }

        // Use the first eligible state (preferred) or first uncorrelated component as the representative
        ComponentVulnerabilityState primaryState = eligibleStates.isEmpty() ? null : eligibleStates.get(0);
        InventoryComponent primaryComponent = primaryState != null
                ? primaryState.getComponent()
                : uncorrelatedComponents.get(0);
        Asset primaryAsset = primaryComponent.getAsset();

        // Build grouped evidence
        Map<String, Object> evidenceMap = new LinkedHashMap<>();
        evidenceMap.put("source", "manual-org-cve-review");
        evidenceMap.put("analyst", userId);
        evidenceMap.put("justification", normalizedJustification);
        evidenceMap.put("findingCreationMode", "CVE_FIX");
        evidenceMap.put("groupedFinding", true);
        evidenceMap.put("affectedAssetCount", affectedAssets.size());
        evidenceMap.put("affectedAssets", affectedAssets);
        evidenceMap.put("effectiveApplicabilityState", ApplicabilityState.APPLICABLE.name());
        evidenceMap.put("effectiveAnalystDisposition", AnalystDisposition.IMPACTED.name());
        evidenceMap.put("analystOverrideApplied", true);
        String groupedEvidence = toJson(evidenceMap);

        double riskScore = findingsScoreService.computeFromParts(
                policy.getFindingsScoreConfig(), vulnerability, primaryAsset, primaryComponent, severityOverride);

        // Look for any existing grouped finding by parsing the groupedFinding flag in evidence.
        // We must NOT match only by primaryComponent.getId() because the "primary" component can differ
        // between calls when there are multiple eligible assets with the same name/version — the sort
        // order is stable within a single call but not guaranteed to be the same across calls.
        // When forceNew=true the caller explicitly requested a brand-new finding, so skip the lookup.
        List<Finding> existingFindings =
                findingRepository.findByTenant_IdAndVulnerability_Id(tenant.getId(), vulnerability.getId());
        Finding existingGrouped = forceNew ? null : existingFindings.stream()
                .filter(f -> {
                    if (f.getEvidence() == null || f.getEvidence().isBlank()) return false;
                    try {
                        JsonNode ev = objectMapper.readTree(f.getEvidence());
                        return ev.path("groupedFinding").asBoolean(false);
                    } catch (Exception e) {
                        return false;
                    }
                })
                .findFirst()
                .orElse(null);

        if (existingGrouped != null) {
            // Merge newly selected assets with those already recorded in the existing finding's evidence,
            // so that "Add to existing finding" accumulates rather than replaces.
            String mergedEvidence = buildMergedGroupedEvidence(evidenceMap, affectedAssets, existingGrouped.getEvidence());
            int mergedAssetCount = countAffectedAssetsInEvidence(mergedEvidence);

            if (existingGrouped.getStatus() == FindingStatus.RESOLVED || existingGrouped.getStatus() == FindingStatus.AUTO_CLOSED) {
                existingGrouped.setStatus(FindingStatus.OPEN);
                existingGrouped.setDecisionState(FindingDecisionState.AFFECTED);
                existingGrouped.setRiskScore(riskScore);
                existingGrouped.setDueAt(dueDateOverride != null ? dueDateOverride : findingSlaService.deriveDueAt(existingGrouped.getFirstObservedAt(), riskScore, primaryAsset, policy));
                if (severityOverride != null && !severityOverride.isBlank()) {
                    existingGrouped.setSeverityOverride(severityOverride.toUpperCase());
                }
                applyManualEvidence(existingGrouped, mergedEvidence);
                existingGrouped.setLastObservedAt(now);
                existingGrouped.touch();
                findingRepository.save(existingGrouped);
                findingWorkflowService.appendEvent(existingGrouped, "REOPENED_BY_MANUAL_CVE_REVIEW", userId,
                        "Grouped finding (CVE+Fix) reopened", Map.of("affectedAssetCount", mergedAssetCount));
                orgCveRecordService.refreshForTenantAndVulnerabilities(tenant, List.of(vulnerability.getId()));
                return new ManualFindingCreationResult(totalEligible, 0, 1, 0);
            }
            // Already open — merge new assets into the evidence.
            applyManualEvidence(existingGrouped, mergedEvidence);
            existingGrouped.setLastObservedAt(now);
            existingGrouped.touch();
            findingRepository.save(existingGrouped);
            findingWorkflowService.appendEvent(existingGrouped, "UPDATED_BY_MANUAL_CVE_REVIEW", userId,
                    "Grouped finding (CVE+Fix) evidence updated", Map.of("affectedAssetCount", mergedAssetCount));
            return new ManualFindingCreationResult(totalEligible, 0, 0, 1);
        }

        Finding grouped = new Finding();
        grouped.setTenant(tenant);
        grouped.setAsset(primaryAsset);
        grouped.setComponent(primaryComponent);
        grouped.setVulnerability(vulnerability);
        grouped.setStatus(FindingStatus.OPEN);
        grouped.setDecisionState(FindingDecisionState.AFFECTED);
        grouped.setMatchedBy("manual-org-cve-review-cve-fix");
        grouped.setRiskScore(riskScore);
        grouped.setConfidenceScore(primaryState != null && primaryState.getConfidenceScore() != null ? primaryState.getConfidenceScore() : 0.0);
        grouped.setFirstObservedAt(now);
        grouped.setLastObservedAt(now);
        grouped.setDueAt(dueDateOverride != null ? dueDateOverride : findingSlaService.deriveDueAt(now, riskScore, primaryAsset, policy));
        if (severityOverride != null && !severityOverride.isBlank()) {
            grouped.setSeverityOverride(severityOverride.toUpperCase());
        }
        grouped.setSuppressionReason(null);
        grouped.setSuppressedUntil(null);
        applyManualEvidence(grouped, groupedEvidence);
        if (primaryState != null) {
            grouped.setPrecedenceTrace(primaryState.getTraceJson());
        }
        grouped.touch();

        findingRepository.save(grouped);
        findingWorkflowService.appendEvent(grouped, "CREATED_BY_MANUAL_CVE_REVIEW", userId,
                "Grouped finding (CVE+Fix) created covering " + affectedAssets.size() + " affected assets",
                Map.of("justification", normalizedJustification, "affectedAssetCount", affectedAssets.size()));

        orgCveRecordService.refreshForTenantAndVulnerabilities(tenant, List.of(vulnerability.getId()));
        return new ManualFindingCreationResult(totalEligible, 1, 0, 0);
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
            RiskPolicy policy,
            String severityOverride,
            Instant dueDateOverride
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
        finding.setDueAt(dueDateOverride != null ? dueDateOverride : findingSlaService.deriveDueAt(now, riskScore, asset, policy));
        if (severityOverride != null && !severityOverride.isBlank()) {
            finding.setSeverityOverride(severityOverride.toUpperCase());
        }
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

    private Map<String, Object> buildAffectedAssetEntry(InventoryComponent comp) {
        Asset asset = comp.getAsset();
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("componentId", comp.getId().toString());
        entry.put("assetId", asset.getId() != null ? asset.getId().toString() : null);
        entry.put("assetIdentifier", asset.getIdentifier());
        entry.put("assetName", asset.getName());
        entry.put("packageName", comp.getPackageName());
        entry.put("version", comp.getVersion());
        entry.put("assetType", asset.getType() != null ? asset.getType().toString() : null);
        entry.put("businessCriticality", asset.getBusinessCriticality() != null ? asset.getBusinessCriticality().name() : null);
        entry.put("environment", asset.getEnvironment());
        return entry;
    }

    /**
     * Builds grouped evidence JSON that merges {@code newAssets} with any assets already
     * recorded in {@code existingEvidence}.  New entries take precedence (they are listed
     * first); existing entries whose componentId is not present in the new batch are appended,
     * so no previously-linked asset is lost.
     */
    @SuppressWarnings("unchecked")
    private String buildMergedGroupedEvidence(Map<String, Object> evidenceTemplate,
                                               List<Map<String, Object>> newAssets,
                                               String existingEvidence) {
        List<Map<String, Object>> merged = new ArrayList<>(newAssets);
        Set<String> newIds = newAssets.stream()
                .map(a -> (String) a.get("componentId"))
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());

        if (existingEvidence != null && !existingEvidence.isBlank()) {
            try {
                JsonNode ev = objectMapper.readTree(existingEvidence);
                JsonNode existingArray = ev.path("affectedAssets");
                if (existingArray.isArray()) {
                    for (JsonNode node : existingArray) {
                        String cid = node.path("componentId").asText(null);
                        if (cid != null && !newIds.contains(cid)) {
                            Map<String, Object> entry = objectMapper.convertValue(node, Map.class);
                            merged.add(entry);
                        }
                    }
                }
            } catch (Exception ignored) {
                // If the existing evidence cannot be parsed, proceed with the new assets only.
            }
        }

        Map<String, Object> mergedMap = new LinkedHashMap<>(evidenceTemplate);
        mergedMap.put("affectedAssetCount", merged.size());
        mergedMap.put("affectedAssets", merged);
        return toJson(mergedMap);
    }

    private int countAffectedAssetsInEvidence(String evidence) {
        if (evidence == null || evidence.isBlank()) return 0;
        try {
            JsonNode ev = objectMapper.readTree(evidence);
            JsonNode arr = ev.path("affectedAssets");
            return arr.isArray() ? arr.size() : ev.path("affectedAssetCount").asInt(0);
        } catch (Exception e) {
            return 0;
        }
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

    private String buildUncorrelatedFindingEvidence(String justification, String createdBy) {
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("source", "manual-org-cve-review");
        evidence.put("analyst", createdBy);
        evidence.put("justification", justification);
        evidence.put("matchedBy", "manual-org-cve-review");
        evidence.put("effectiveApplicabilityState", ApplicabilityState.APPLICABLE.name());
        evidence.put("effectiveAnalystDisposition", AnalystDisposition.IMPACTED.name());
        evidence.put("analystOverrideApplied", true);
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
