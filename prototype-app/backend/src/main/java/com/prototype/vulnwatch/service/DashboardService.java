package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.ApplicabilityState;
import com.prototype.vulnwatch.domain.ComponentVulnerabilityState;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingEvent;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.ImpactState;
import com.prototype.vulnwatch.domain.InventoryComponentCpeMap;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import com.prototype.vulnwatch.domain.VulnerabilityTargetType;
import com.prototype.vulnwatch.dto.ApplicableSoftwarePageResponse;
import com.prototype.vulnwatch.dto.ApplicableSoftwareRecordResponse;
import com.prototype.vulnwatch.dto.CveInventoryMappingRecordResponse;
import com.prototype.vulnwatch.dto.DashboardCsafVexAnalyticsResponse;
import com.prototype.vulnwatch.dto.DashboardCveInventoryMapResponse;
import com.prototype.vulnwatch.dto.DashboardCorrelationEfficiencyResponse;
import com.prototype.vulnwatch.dto.DashboardNoiseReductionResponse;
import com.prototype.vulnwatch.dto.DashboardResponse;
import com.prototype.vulnwatch.dto.FindingResponse;
import com.prototype.vulnwatch.dto.ImpactedCvePageResponse;
import com.prototype.vulnwatch.dto.ImpactedCveRecordResponse;
import com.prototype.vulnwatch.dto.TopFindingMetricResponse;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.ComponentVulnerabilityStateRepository;
import com.prototype.vulnwatch.repo.FindingEventRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.InventoryComponentCpeMapRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.SyncRunRepository;
import com.prototype.vulnwatch.repo.VulnerabilityTargetRepository;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class DashboardService {

    private static final Set<ImpactState> FINDING_ELIGIBLE_IMPACT_STATES = Set.of(ImpactState.IMPACTED, ImpactState.NO_PATCH);

    private final AssetRepository assetRepository;
    private final InventoryComponentRepository inventoryComponentRepository;
    private final InventoryComponentCpeMapRepository inventoryComponentCpeMapRepository;
    private final ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository;
    private final VulnerabilityTargetRepository vulnerabilityTargetRepository;
    private final FindingRepository findingRepository;
    private final FindingEventRepository findingEventRepository;
    private final FindingService findingService;
    private final SyncRunRepository syncRunRepository;
    private final ObjectMapper objectMapper;

    public DashboardService(
            AssetRepository assetRepository,
            InventoryComponentRepository inventoryComponentRepository,
            InventoryComponentCpeMapRepository inventoryComponentCpeMapRepository,
            ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository,
            VulnerabilityTargetRepository vulnerabilityTargetRepository,
            FindingRepository findingRepository,
            FindingEventRepository findingEventRepository,
            FindingService findingService,
            SyncRunRepository syncRunRepository,
            ObjectMapper objectMapper
    ) {
        this.assetRepository = assetRepository;
        this.inventoryComponentRepository = inventoryComponentRepository;
        this.inventoryComponentCpeMapRepository = inventoryComponentCpeMapRepository;
        this.componentVulnerabilityStateRepository = componentVulnerabilityStateRepository;
        this.vulnerabilityTargetRepository = vulnerabilityTargetRepository;
        this.findingRepository = findingRepository;
        this.findingEventRepository = findingEventRepository;
        this.findingService = findingService;
        this.syncRunRepository = syncRunRepository;
        this.objectMapper = objectMapper;
    }

    public DashboardResponse get(Tenant tenant) {
        long assets = assetRepository.countByTenant(tenant);
        long components = inventoryComponentRepository.countByTenantAndComponentStatus(tenant, InventoryComponentStatus.ACTIVE);
        long openFindings = findingService.countOpen(tenant);
        long criticalFindings = findingService.countCritical(tenant);
        long openCritical = findingRepository.countByTenantAndStatusAndSeverity(tenant, FindingStatus.OPEN, "CRITICAL");
        long openHigh = findingRepository.countByTenantAndStatusAndSeverity(tenant, FindingStatus.OPEN, "HIGH");
        long openMedium = findingRepository.countByTenantAndStatusAndSeverity(tenant, FindingStatus.OPEN, "MEDIUM");
        long openLow = findingRepository.countByTenantAndStatusAndSeverity(tenant, FindingStatus.OPEN, "LOW");
        double averageOpenRisk = findingRepository.averageRiskScoreByTenantAndStatus(tenant, FindingStatus.OPEN);
        double averageOpenConfidence = findingRepository.averageConfidenceScoreByTenantAndStatus(tenant, FindingStatus.OPEN);
        long highConfidenceOpen = findingRepository.countByTenantAndStatusAndConfidenceScoreGreaterThanEqual(
                tenant,
                FindingStatus.OPEN,
                0.8);
        List<TopFindingMetricResponse> topVulnerabilities = findingRepository.findTopVulnerabilitiesByTenantAndStatus(
                tenant,
                FindingStatus.OPEN,
                PageRequest.of(0, 5));
        List<TopFindingMetricResponse> topInstalledComponents = findingRepository.findTopInstalledComponentsByTenantAndStatus(
                tenant,
                FindingStatus.OPEN,
                PageRequest.of(0, 5));
        List<TopFindingMetricResponse> topAssetsAtRisk = findingRepository.findTopAssetsByTenantAndStatus(
                tenant,
                FindingStatus.OPEN,
                PageRequest.of(0, 5));
        List<TopFindingMetricResponse> topVulnerabilityProductIdentities =
                findingRepository.findTopVulnerabilityProductIdentitiesByTenantAndStatus(
                        tenant,
                        FindingStatus.OPEN,
                        PageRequest.of(0, 5));
        List<FindingResponse> latest = findingService.listLatestByTenant(tenant, 10);
        DashboardNoiseReductionResponse noiseReduction = buildNoiseReduction(tenant, openFindings);
        DashboardCsafVexAnalyticsResponse csafVexAnalytics = buildCsafVexAnalytics(tenant, noiseReduction);
        DashboardCorrelationEfficiencyResponse correlationEfficiency = buildCorrelationEfficiency(tenant, components);

        return new DashboardResponse(
                assets,
                components,
                openFindings,
                criticalFindings,
                openCritical,
                openHigh,
                openMedium,
                openLow,
                averageOpenRisk,
                averageOpenConfidence,
                highConfidenceOpen,
                topVulnerabilities,
                topInstalledComponents,
                topAssetsAtRisk,
                topVulnerabilityProductIdentities,
                latest,
                noiseReduction,
                csafVexAnalytics,
                correlationEfficiency);
    }

    @Transactional(readOnly = true)
    public ApplicableSoftwarePageResponse listApplicableSoftware(Tenant tenant, int page, int size) {
        int safePage = Math.max(0, page);
        int safeSize = Math.max(1, Math.min(200, size));
        long totalItems = componentVulnerabilityStateRepository.countDistinctComponent_IdByTenantAndApplicabilityState(
                tenant,
                ApplicabilityState.APPLICABLE
        );
        int totalPages = totalItems <= 0L ? 0 : (int) Math.ceil((double) totalItems / (double) safeSize);

        List<ComponentVulnerabilityStateRepository.ApplicableSoftwareAggregateRow> rows =
                componentVulnerabilityStateRepository.findApplicableSoftwareAggregates(
                        tenant,
                        ApplicabilityState.APPLICABLE,
                        FINDING_ELIGIBLE_IMPACT_STATES,
                        PageRequest.of(safePage, safeSize)
                );

        List<ApplicableSoftwareRecordResponse> items = rows.stream()
                .map(row -> new ApplicableSoftwareRecordResponse(
                        row.getComponentId(),
                        row.getAssetId(),
                        row.getAssetName(),
                        row.getAssetIdentifier(),
                        row.getEcosystem(),
                        row.getPackageName(),
                        row.getVersion(),
                        row.getApplicableCount(),
                        row.getImpactedCount(),
                        row.getNoPatchCount(),
                        row.getLastEvaluatedAt()
                ))
                .toList();

        return new ApplicableSoftwarePageResponse(
                items,
                safePage,
                safeSize,
                totalItems,
                totalPages
        );
    }

    @Transactional(readOnly = true)
    public ImpactedCvePageResponse listImpactedCves(Tenant tenant, int page, int size) {
        int safePage = Math.max(0, page);
        int safeSize = Math.max(1, Math.min(200, size));
        long totalItems = componentVulnerabilityStateRepository.countDistinctVulnerability_IdByTenantAndImpactStateIn(
                tenant,
                FINDING_ELIGIBLE_IMPACT_STATES
        );
        int totalPages = totalItems <= 0L ? 0 : (int) Math.ceil((double) totalItems / (double) safeSize);

        List<ComponentVulnerabilityStateRepository.ImpactedCveAggregateRow> rows =
                componentVulnerabilityStateRepository.findImpactedCveAggregates(
                        tenant,
                        FINDING_ELIGIBLE_IMPACT_STATES,
                        PageRequest.of(safePage, safeSize)
                );

        List<ImpactedCveRecordResponse> items = rows.stream()
                .map(this::toImpactedCveRecord)
                .toList();

        return new ImpactedCvePageResponse(
                items,
                safePage,
                safeSize,
                totalItems,
                totalPages
        );
    }

    @Transactional(readOnly = true)
    public DashboardCveInventoryMapResponse getCveInventoryMap(Tenant tenant, int limit) {
        int safeLimit = Math.max(1, Math.min(50, limit));
        List<UUID> highRiskIds = componentVulnerabilityStateRepository.findImpactedVulnerabilityIdsByRisk(
                tenant,
                FINDING_ELIGIBLE_IMPACT_STATES,
                PageRequest.of(0, safeLimit)
        );
        List<UUID> latestIds = componentVulnerabilityStateRepository.findImpactedVulnerabilityIdsByLatest(
                tenant,
                FINDING_ELIGIBLE_IMPACT_STATES,
                PageRequest.of(0, safeLimit)
        );

        Set<UUID> requestedIds = new LinkedHashSet<>();
        requestedIds.addAll(highRiskIds);
        requestedIds.addAll(latestIds);
        if (requestedIds.isEmpty()) {
            return new DashboardCveInventoryMapResponse(List.of(), List.of());
        }

        List<ComponentVulnerabilityStateRepository.ImpactedCveAggregateRow> aggregateRows =
                componentVulnerabilityStateRepository.findImpactedCveAggregatesByVulnerabilityIds(
                        tenant,
                        FINDING_ELIGIBLE_IMPACT_STATES,
                        requestedIds
                );
        Map<UUID, ComponentVulnerabilityStateRepository.ImpactedCveAggregateRow> aggregatesByVulnerability = new HashMap<>();
        for (ComponentVulnerabilityStateRepository.ImpactedCveAggregateRow row : aggregateRows) {
            if (row.getVulnerabilityId() == null) {
                continue;
            }
            aggregatesByVulnerability.put(row.getVulnerabilityId(), row);
        }

        List<ComponentVulnerabilityState> impactedStates =
                componentVulnerabilityStateRepository.findByTenant_IdAndVulnerability_IdInAndImpactStateIn(
                        tenant.getId(),
                        requestedIds,
                        FINDING_ELIGIBLE_IMPACT_STATES
                );

        Map<UUID, LinkedHashSet<String>> mappedSoftwareByVulnerability = new HashMap<>();
        Map<UUID, Set<UUID>> componentIdsByVulnerability = new HashMap<>();
        for (ComponentVulnerabilityState state : impactedStates) {
            if (state.getVulnerability() == null
                    || state.getVulnerability().getId() == null
                    || state.getComponent() == null
                    || state.getComponent().getId() == null) {
                continue;
            }
            UUID vulnerabilityId = state.getVulnerability().getId();
            componentIdsByVulnerability
                    .computeIfAbsent(vulnerabilityId, ignored -> new HashSet<>())
                    .add(state.getComponent().getId());
            mappedSoftwareByVulnerability
                    .computeIfAbsent(vulnerabilityId, ignored -> new LinkedHashSet<>())
                    .add(toSoftwareInventoryLabel(state));
        }

        List<VulnerabilityTarget> targets = vulnerabilityTargetRepository.findByVulnerability_IdInAndTargetType(
                requestedIds,
                VulnerabilityTargetType.CPE
        );
        Map<UUID, LinkedHashSet<String>> targetCpesByVulnerability = new HashMap<>();
        for (VulnerabilityTarget target : targets) {
            if (target.getVulnerability() == null || target.getVulnerability().getId() == null) {
                continue;
            }
            String cpe = normalizedCpe(target);
            if (!hasText(cpe)) {
                continue;
            }
            targetCpesByVulnerability
                    .computeIfAbsent(target.getVulnerability().getId(), ignored -> new LinkedHashSet<>())
                    .add(cpe);
        }

        Set<UUID> allImpactedComponentIds = componentIdsByVulnerability.values().stream()
                .flatMap(Collection::stream)
                .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));
        List<InventoryComponentCpeMap> componentCpeMaps = allImpactedComponentIds.isEmpty()
                ? List.of()
                : inventoryComponentCpeMapRepository.findByTenant_IdAndComponent_IdIn(tenant.getId(), allImpactedComponentIds);

        Map<UUID, Set<String>> cpesByComponentId = new HashMap<>();
        for (InventoryComponentCpeMap map : componentCpeMaps) {
            if (map.getComponent() == null || map.getComponent().getId() == null) {
                continue;
            }
            String cpe = map.getCpeDim() == null ? null : map.getCpeDim().getNormalizedCpe();
            if (!hasText(cpe)) {
                continue;
            }
            cpesByComponentId.computeIfAbsent(map.getComponent().getId(), ignored -> new HashSet<>()).add(cpe);
        }

        List<CveInventoryMappingRecordResponse> highRisk = buildCveInventoryMappings(
                highRiskIds,
                aggregatesByVulnerability,
                mappedSoftwareByVulnerability,
                componentIdsByVulnerability,
                targetCpesByVulnerability,
                cpesByComponentId
        );
        List<CveInventoryMappingRecordResponse> latest = buildCveInventoryMappings(
                latestIds,
                aggregatesByVulnerability,
                mappedSoftwareByVulnerability,
                componentIdsByVulnerability,
                targetCpesByVulnerability,
                cpesByComponentId
        );

        return new DashboardCveInventoryMapResponse(highRisk, latest);
    }

    private ImpactedCveRecordResponse toImpactedCveRecord(
            ComponentVulnerabilityStateRepository.ImpactedCveAggregateRow row
    ) {
        return new ImpactedCveRecordResponse(
                row.getVulnerabilityId(),
                row.getExternalId(),
                row.getSeverity(),
                row.getCvssScore(),
                row.getEpssScore(),
                row.isInKev(),
                row.getImpactedComponentCount(),
                row.getImpactedAssetCount(),
                row.getNoPatchComponentCount(),
                row.getLastEvaluatedAt(),
                row.getLastModifiedAt()
        );
    }

    private List<CveInventoryMappingRecordResponse> buildCveInventoryMappings(
            List<UUID> vulnerabilityIds,
            Map<UUID, ComponentVulnerabilityStateRepository.ImpactedCveAggregateRow> aggregatesByVulnerability,
            Map<UUID, LinkedHashSet<String>> mappedSoftwareByVulnerability,
            Map<UUID, Set<UUID>> componentIdsByVulnerability,
            Map<UUID, LinkedHashSet<String>> targetCpesByVulnerability,
            Map<UUID, Set<String>> cpesByComponentId
    ) {
        if (vulnerabilityIds == null || vulnerabilityIds.isEmpty()) {
            return List.of();
        }

        List<CveInventoryMappingRecordResponse> items = new ArrayList<>();
        Set<UUID> seen = new HashSet<>();
        for (UUID vulnerabilityId : vulnerabilityIds) {
            if (vulnerabilityId == null || !seen.add(vulnerabilityId)) {
                continue;
            }
            ComponentVulnerabilityStateRepository.ImpactedCveAggregateRow row =
                    aggregatesByVulnerability.get(vulnerabilityId);
            if (row == null) {
                continue;
            }

            LinkedHashSet<String> mappedCpes = new LinkedHashSet<>();
            LinkedHashSet<String> targetCpesSet = targetCpesByVulnerability.get(vulnerabilityId);
            Set<String> targetCpes = targetCpesSet == null ? Set.of() : targetCpesSet;
            Set<UUID> componentIds = componentIdsByVulnerability.getOrDefault(vulnerabilityId, Set.of());
            for (UUID componentId : componentIds) {
                Set<String> inventoryCpes = cpesByComponentId.getOrDefault(componentId, Set.of());
                if (inventoryCpes.isEmpty()) {
                    continue;
                }
                if (targetCpes.isEmpty()) {
                    mappedCpes.addAll(inventoryCpes);
                    continue;
                }
                for (String inventoryCpe : inventoryCpes) {
                    if (targetCpes.contains(inventoryCpe)) {
                        mappedCpes.add(inventoryCpe);
                    }
                }
            }
            if (mappedCpes.isEmpty() && !targetCpes.isEmpty()) {
                mappedCpes.addAll(targetCpes);
            }

            List<String> mappedSoftware = new ArrayList<>(mappedSoftwareByVulnerability.getOrDefault(
                    vulnerabilityId,
                    new LinkedHashSet<>()
            ));

            items.add(new CveInventoryMappingRecordResponse(
                    row.getVulnerabilityId(),
                    row.getExternalId(),
                    row.getSeverity(),
                    row.getCvssScore(),
                    row.getEpssScore(),
                    row.isInKev(),
                    row.getImpactedComponentCount(),
                    row.getNoPatchComponentCount(),
                    row.getLastModifiedAt(),
                    List.copyOf(mappedCpes),
                    mappedSoftware,
                    mappedSoftware.size()
            ));
        }
        return items;
    }

    private String toSoftwareInventoryLabel(ComponentVulnerabilityState state) {
        if (state == null || state.getComponent() == null) {
            return "";
        }
        String ecosystem = state.getComponent().getEcosystem();
        String packageName = state.getComponent().getPackageName();
        String version = state.getComponent().getVersion();
        StringBuilder label = new StringBuilder();
        if (hasText(ecosystem)) {
            label.append(ecosystem.trim());
            label.append(":");
        }
        if (hasText(packageName)) {
            label.append(packageName.trim());
        } else {
            label.append("unknown");
        }
        if (hasText(version)) {
            label.append("@");
            label.append(version.trim());
        }
        return label.toString();
    }

    private String normalizedCpe(VulnerabilityTarget target) {
        if (target == null) {
            return null;
        }
        if (target.getCpeDim() != null && hasText(target.getCpeDim().getNormalizedCpe())) {
            return target.getCpeDim().getNormalizedCpe().trim().toLowerCase(Locale.ROOT);
        }
        if (hasText(target.getCpe())) {
            return target.getCpe().trim().toLowerCase(Locale.ROOT);
        }
        if (hasText(target.getNormalizedTargetKey())) {
            return target.getNormalizedTargetKey().trim().toLowerCase(Locale.ROOT);
        }
        if (hasText(target.getRawTarget())) {
            return target.getRawTarget().trim().toLowerCase(Locale.ROOT);
        }
        return null;
    }

    private DashboardCorrelationEfficiencyResponse buildCorrelationEfficiency(Tenant tenant, long activeComponents) {
        long cpeEligibleActiveComponents = inventoryComponentCpeMapRepository
                .countDistinctComponentIdsByTenantAndComponentStatus(tenant, InventoryComponentStatus.ACTIVE);
        long cpeIneligibleActiveComponents = Math.max(0L, activeComponents - cpeEligibleActiveComponents);
        double cpeCoveragePercent = activeComponents <= 0L
                ? 0.0
                : ((double) cpeEligibleActiveComponents * 100.0) / (double) activeComponents;

        List<Finding> openFindings = findingRepository.findByTenantAndStatusOrderByUpdatedAtDesc(tenant, FindingStatus.OPEN);
        long openFindingsMatchedByCpe = 0L;
        long openFindingsCpeDirect = 0L;
        long openFindingsCpeFallback = 0L;
        double totalOpenCpeConfidence = 0.0;

        for (Finding finding : openFindings) {
            if (!isCpeMatchMethod(finding.getMatchedBy())) {
                continue;
            }
            openFindingsMatchedByCpe++;
            totalOpenCpeConfidence += finding.getConfidenceScore();
            String matchedBy = finding.getMatchedBy() == null ? "" : finding.getMatchedBy().trim().toLowerCase(Locale.ROOT);
            if (matchedBy.contains("direct")) {
                openFindingsCpeDirect++;
            } else if (matchedBy.contains("fallback")) {
                openFindingsCpeFallback++;
            }
        }

        double cpeDirectSharePercent = openFindingsMatchedByCpe <= 0L
                ? 0.0
                : ((double) openFindingsCpeDirect * 100.0) / (double) openFindingsMatchedByCpe;
        double cpeFallbackSharePercent = openFindingsMatchedByCpe <= 0L
                ? 0.0
                : ((double) openFindingsCpeFallback * 100.0) / (double) openFindingsMatchedByCpe;
        double averageOpenCpeConfidenceScore = openFindingsMatchedByCpe <= 0L
                ? 0.0
                : totalOpenCpeConfidence / (double) openFindingsMatchedByCpe;

        Instant createdCutoff = Instant.now().minusSeconds(24L * 60L * 60L);
        List<Finding> recentFindings = findingRepository.findByTenantOrderByUpdatedAtDesc(tenant).stream()
                .filter(finding -> finding.getFirstObservedAt() != null && !finding.getFirstObservedAt().isBefore(createdCutoff))
                .toList();
        long cpeFindingsCreatedLast24Hours = recentFindings.stream()
                .filter(finding -> isCpeMatchMethod(finding.getMatchedBy()))
                .count();
        long nonCpeFindingsCreatedLast24Hours = recentFindings.size() - cpeFindingsCreatedLast24Hours;

        return new DashboardCorrelationEfficiencyResponse(
                activeComponents,
                cpeEligibleActiveComponents,
                cpeIneligibleActiveComponents,
                cpeCoveragePercent,
                openFindingsMatchedByCpe,
                openFindingsCpeDirect,
                openFindingsCpeFallback,
                cpeDirectSharePercent,
                cpeFallbackSharePercent,
                averageOpenCpeConfidenceScore,
                cpeFindingsCreatedLast24Hours,
                nonCpeFindingsCreatedLast24Hours
        );
    }

    private DashboardNoiseReductionResponse buildNoiseReduction(Tenant tenant, long openFindings) {
        FindingService.NotApplicableProjection projection = findingService.projectNotApplicableByCorrelation(tenant);
        long neverOpenedNotApplicable = projection.neverOpenedNotApplicable();
        long deferredUnderInvestigation = projection.deferredUnderInvestigation();
        long autoResolvedNotApplicable = findingRepository.countByTenantAndStatusAndDecisionStateWithEvent(
                tenant,
                FindingStatus.RESOLVED,
                FindingDecisionState.NOT_AFFECTED,
                "AUTO_RESOLVED_NOT_OBSERVED"
        );
        long totalFilteredNotApplicable = neverOpenedNotApplicable + autoResolvedNotApplicable;
        long potentialFindingsWithoutCorrelation = openFindings + totalFilteredNotApplicable;
        double filteredPercentOfPotential = potentialFindingsWithoutCorrelation <= 0
                ? 0
                : (double) totalFilteredNotApplicable * 100.0 / (double) potentialFindingsWithoutCorrelation;

        Map<String, Long> categoryCounts = new HashMap<>(projection.categories());
        if (autoResolvedNotApplicable > 0) {
            categoryCounts.merge("Auto-Resolved (No Longer Observed)", autoResolvedNotApplicable, Long::sum);
        }
        List<TopFindingMetricResponse> categories = categoryCounts.entrySet().stream()
                .sorted((left, right) -> Long.compare(right.getValue(), left.getValue()))
                .limit(8)
                .map(entry -> new TopFindingMetricResponse(entry.getKey(), entry.getValue()))
                .toList();

        List<TopFindingMetricResponse> trendLast30Days = buildAutoResolvedTrend(tenant);
        return new DashboardNoiseReductionResponse(
                totalFilteredNotApplicable,
                neverOpenedNotApplicable,
                autoResolvedNotApplicable,
                deferredUnderInvestigation,
                potentialFindingsWithoutCorrelation,
                filteredPercentOfPotential,
                categories,
                trendLast30Days
        );
    }

    private DashboardCsafVexAnalyticsResponse buildCsafVexAnalytics(
            Tenant tenant,
            DashboardNoiseReductionResponse noiseReduction
    ) {
        Instant now = Instant.now();
        Instant fromInclusive = now.minusSeconds(30L * 24L * 60L * 60L);
        List<SyncRun> recentRuns = syncRunRepository.findByStartedAtGreaterThanEqual(fromInclusive);
        List<SyncRun> recentCsafRuns = recentRuns.stream()
                .filter(run -> hasText(run.getSyncType()) && run.getSyncType().toUpperCase(Locale.ROOT).contains("CSAF"))
                .toList();

        long csafRunsLast30Days = recentCsafRuns.size();
        long csafSuccessfulRunsLast30Days = recentCsafRuns.stream()
                .filter(run -> "completed".equalsIgnoreCase(run.getStatus()))
                .filter(run -> !hasText(run.getErrorMessage()))
                .count();
        long csafPartialFailureRunsLast30Days = recentCsafRuns.stream()
                .filter(run -> "completed".equalsIgnoreCase(run.getStatus()))
                .filter(run -> hasText(run.getErrorMessage()))
                .count();

        double csafNormalizationSuccessRate = csafRunsLast30Days == 0L
                ? 0.0
                : ((double) csafSuccessfulRunsLast30Days * 100.0) / (double) csafRunsLast30Days;
        double csafPartialFailureRate = csafRunsLast30Days == 0L
                ? 0.0
                : ((double) csafPartialFailureRunsLast30Days * 100.0) / (double) csafRunsLast30Days;

        Map<String, Long> notApplicableCategories = new HashMap<>();
        for (TopFindingMetricResponse category : noiseReduction.categories()) {
            if (category == null || !hasText(category.key())) {
                continue;
            }
            notApplicableCategories.merge(category.key().trim(), category.count(), Long::sum);
        }
        long findingsSuppressedByVex = categoryCount(notApplicableCategories, "VEX Not Affected")
                + categoryCount(notApplicableCategories, "VEX Fixed");
        long suppressedByStaleVex = categoryCount(notApplicableCategories, "VEX Stale Or Untrusted");

        List<Finding> tenantFindings = findingRepository.findByTenantOrderByUpdatedAtDesc(tenant);
        Map<String, Long> providerCounts = new HashMap<>();
        long underInvestigationAging = 0L;
        Instant underInvestigationAgingCutoff = now.minusSeconds(14L * 24L * 60L * 60L);
        for (Finding finding : tenantFindings) {
            if (finding == null) {
                continue;
            }
            VexEvidence vex = parseVexEvidence(finding.getEvidence());
            if (finding.getStatus() == FindingStatus.OPEN && hasText(vex.provider())) {
                providerCounts.merge(vex.provider(), 1L, Long::sum);
            }
            if (finding.getStatus() == FindingStatus.OPEN
                    && finding.getDecisionState() == FindingDecisionState.UNDER_INVESTIGATION
                    && finding.getFirstObservedAt() != null
                    && finding.getFirstObservedAt().isBefore(underInvestigationAgingCutoff)) {
                underInvestigationAging++;
            }
        }

        List<TopFindingMetricResponse> vexCoverageByProvider = providerCounts.entrySet().stream()
                .sorted((left, right) -> Long.compare(right.getValue(), left.getValue()))
                .limit(8)
                .map(entry -> new TopFindingMetricResponse(entry.getKey(), entry.getValue()))
                .toList();

        List<TopFindingMetricResponse> staleSuppressionTrendLast30Days = buildStaleSuppressionTrend(tenantFindings);
        return new DashboardCsafVexAnalyticsResponse(
                csafRunsLast30Days,
                csafSuccessfulRunsLast30Days,
                csafPartialFailureRunsLast30Days,
                csafNormalizationSuccessRate,
                csafPartialFailureRate,
                findingsSuppressedByVex,
                suppressedByStaleVex,
                underInvestigationAging,
                vexCoverageByProvider,
                staleSuppressionTrendLast30Days
        );
    }

    private List<TopFindingMetricResponse> buildStaleSuppressionTrend(List<Finding> findings) {
        LocalDate todayUtc = LocalDate.now(ZoneOffset.UTC);
        LocalDate startDate = todayUtc.minusDays(29);
        Map<LocalDate, Long> countsByDay = new TreeMap<>();
        LocalDate cursor = startDate;
        while (!cursor.isAfter(todayUtc)) {
            countsByDay.put(cursor, 0L);
            cursor = cursor.plusDays(1);
        }

        for (Finding finding : findings) {
            if (finding == null || finding.getStatus() != FindingStatus.SUPPRESSED || finding.getUpdatedAt() == null) {
                continue;
            }
            VexEvidence vex = parseVexEvidence(finding.getEvidence());
            if (!"STALE".equals(vex.freshness())) {
                continue;
            }
            LocalDate day = finding.getUpdatedAt().atZone(ZoneOffset.UTC).toLocalDate();
            if (day.isBefore(startDate) || day.isAfter(todayUtc)) {
                continue;
            }
            countsByDay.merge(day, 1L, Long::sum);
        }

        List<TopFindingMetricResponse> trend = new ArrayList<>(countsByDay.size());
        for (Map.Entry<LocalDate, Long> entry : countsByDay.entrySet()) {
            trend.add(new TopFindingMetricResponse(entry.getKey().toString(), entry.getValue()));
        }
        return trend;
    }

    private long categoryCount(Map<String, Long> categories, String key) {
        if (categories == null || !hasText(key)) {
            return 0L;
        }
        Long value = categories.get(key);
        return value == null ? 0L : value;
    }

    private VexEvidence parseVexEvidence(String evidenceJson) {
        if (!hasText(evidenceJson)) {
            return new VexEvidence("UNKNOWN", "UNKNOWN", "unknown");
        }
        try {
            JsonNode root = objectMapper.readTree(evidenceJson);
            JsonNode overlay = root.path("vexOverlay");
            String overlayStatus = normalizeStatus(overlay.path("status").asText(""));
            String overlayFreshness = normalizeFreshness(overlay.path("freshness").asText(""));
            String overlayProvider = normalizeProvider(overlay.path("provider").asText(""));
            if (!"UNKNOWN".equals(overlayStatus) || !"UNKNOWN".equals(overlayFreshness) || !"unknown".equals(overlayProvider)) {
                return new VexEvidence(overlayStatus, overlayFreshness, overlayProvider);
            }
            JsonNode trace = root.path("applicabilityTrace");
            String status = traceValue(trace, "vexStatus");
            String freshnessOutcome = traceValue(trace, "vexFreshnessOutcome");
            String provider = traceValue(trace, "vexProvider");
            return new VexEvidence(
                    normalizeStatus(status),
                    normalizeFreshness(freshnessOutcome),
                    normalizeProvider(provider)
            );
        } catch (Exception ignored) {
            return new VexEvidence("UNKNOWN", "UNKNOWN", "unknown");
        }
    }

    private String traceValue(JsonNode trace, String key) {
        if (trace == null || trace.isMissingNode() || trace.isNull() || !hasText(key)) {
            return null;
        }
        String direct = trace.path(key).asText("");
        if (hasText(direct)) {
            return direct.trim();
        }
        String nested = trace.path("baseApplicability").path(key).asText("");
        if (hasText(nested)) {
            return nested.trim();
        }
        return null;
    }

    private String normalizeStatus(String value) {
        if (!hasText(value)) {
            return "UNKNOWN";
        }
        String normalized = value.trim().toUpperCase(Locale.ROOT);
        if (normalized.contains("AFFECTED") && !normalized.contains("NOT_AFFECTED")) {
            return "AFFECTED";
        }
        if (normalized.contains("NOT_AFFECTED")) {
            return "NOT_AFFECTED";
        }
        if (normalized.contains("FIXED")) {
            return "FIXED";
        }
        if (normalized.contains("UNDER_INVESTIGATION")) {
            return "UNDER_INVESTIGATION";
        }
        return "UNKNOWN";
    }

    private String normalizeFreshness(String value) {
        if (!hasText(value)) {
            return "UNKNOWN";
        }
        String normalized = value.trim().toUpperCase(Locale.ROOT);
        if ("NO_DATE_ASSUME_FRESH".equals(normalized)) {
            return "UNKNOWN";
        }
        if (normalized.contains("STALE")) {
            return "STALE";
        }
        if (normalized.contains("FRESH")) {
            return "FRESH";
        }
        return "UNKNOWN";
    }

    private String normalizeProvider(String value) {
        if (!hasText(value)) {
            return "unknown";
        }
        return value.trim().toLowerCase(Locale.ROOT);
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private boolean isCpeMatchMethod(String matchedBy) {
        if (!hasText(matchedBy)) {
            return false;
        }
        return matchedBy.trim().toLowerCase(Locale.ROOT).startsWith("cpe-");
    }

    private record VexEvidence(
            String status,
            String freshness,
            String provider
    ) {
    }

    private List<TopFindingMetricResponse> buildAutoResolvedTrend(Tenant tenant) {
        LocalDate todayUtc = LocalDate.now(ZoneOffset.UTC);
        LocalDate startDate = todayUtc.minusDays(29);
        Instant fromInclusive = startDate.atStartOfDay().toInstant(ZoneOffset.UTC);
        List<FindingEvent> events = findingEventRepository.findByTenantAndEventTypeSince(
                tenant,
                "AUTO_RESOLVED_NOT_OBSERVED",
                fromInclusive
        );

        Map<LocalDate, Long> countsByDay = new TreeMap<>();
        LocalDate cursor = startDate;
        while (!cursor.isAfter(todayUtc)) {
            countsByDay.put(cursor, 0L);
            cursor = cursor.plusDays(1);
        }
        for (FindingEvent event : events) {
            LocalDate day = event.getCreatedAt().atZone(ZoneOffset.UTC).toLocalDate();
            if (day.isBefore(startDate) || day.isAfter(todayUtc)) {
                continue;
            }
            countsByDay.merge(day, 1L, Long::sum);
        }

        List<TopFindingMetricResponse> trend = new ArrayList<>(countsByDay.size());
        for (Map.Entry<LocalDate, Long> entry : countsByDay.entrySet()) {
            trend.add(new TopFindingMetricResponse(entry.getKey().toString(), entry.getValue()));
        }
        return trend;
    }
}
