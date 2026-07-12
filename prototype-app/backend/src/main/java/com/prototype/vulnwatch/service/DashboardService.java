package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.ApplicabilityState;
import com.prototype.vulnwatch.domain.AssetType;
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
import com.prototype.vulnwatch.dto.ApplicableSoftwarePageResponse;
import com.prototype.vulnwatch.dto.ApplicableSoftwareRecordResponse;
import com.prototype.vulnwatch.dto.CveInventoryMappingRecordResponse;
import com.prototype.vulnwatch.dto.DashboardCsafVexAnalyticsResponse;
import com.prototype.vulnwatch.dto.DashboardCveInventoryMapResponse;
import com.prototype.vulnwatch.dto.DashboardCorrelationEfficiencyResponse;
import com.prototype.vulnwatch.dto.DashboardNoiseReductionResponse;
import com.prototype.vulnwatch.dto.DashboardResponse;
import com.prototype.vulnwatch.dto.FindingResponse;
import com.prototype.vulnwatch.dto.GridExposureResponse;
import com.prototype.vulnwatch.dto.GridExposureRowResponse;
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
import com.prototype.vulnwatch.util.IdentityUtil;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
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
import org.springframework.cache.annotation.Cacheable;
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
    private final FindingRepository findingRepository;
    private final FindingEventRepository findingEventRepository;
    private final FindingQueryService findingQueryService;
    private final DashboardNoiseReductionProjectionService dashboardNoiseReductionProjectionService;
    private final SyncRunRepository syncRunRepository;
    private final ObjectMapper objectMapper;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;

    public DashboardService(
            AssetRepository assetRepository,
            InventoryComponentRepository inventoryComponentRepository,
            InventoryComponentCpeMapRepository inventoryComponentCpeMapRepository,
            ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository,
            FindingRepository findingRepository,
            FindingEventRepository findingEventRepository,
            FindingQueryService findingQueryService,
            DashboardNoiseReductionProjectionService dashboardNoiseReductionProjectionService,
            SyncRunRepository syncRunRepository,
            ObjectMapper objectMapper,
            TenantSchemaExecutionService tenantSchemaExecutionService
    ) {
        this.assetRepository = assetRepository;
        this.inventoryComponentRepository = inventoryComponentRepository;
        this.inventoryComponentCpeMapRepository = inventoryComponentCpeMapRepository;
        this.componentVulnerabilityStateRepository = componentVulnerabilityStateRepository;
        this.findingRepository = findingRepository;
        this.findingEventRepository = findingEventRepository;
        this.findingQueryService = findingQueryService;
        this.dashboardNoiseReductionProjectionService = dashboardNoiseReductionProjectionService;
        this.syncRunRepository = syncRunRepository;
        this.objectMapper = objectMapper;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
    }

    @Cacheable(value = "dashboard", key = "#tenant.id")
    public DashboardResponse get(Tenant tenant) {
        long assets = tenantSchemaExecutionService.run(tenant, () -> assetRepository.count());
        long components = tenantSchemaExecutionService.run(
                tenant,
                () -> inventoryComponentRepository.countByComponentStatus(InventoryComponentStatus.ACTIVE)
        );
        long openFindings = findingQueryService.countOpen(tenant);
        long criticalFindings = findingQueryService.countCritical(tenant);
        long openCritical = tenantSchemaExecutionService.run(tenant, () -> findingRepository.countByStatusAndSeverity(FindingStatus.OPEN, "CRITICAL"));
        long openHigh = tenantSchemaExecutionService.run(tenant, () -> findingRepository.countByStatusAndSeverity(FindingStatus.OPEN, "HIGH"));
        long openMedium = tenantSchemaExecutionService.run(tenant, () -> findingRepository.countByStatusAndSeverity(FindingStatus.OPEN, "MEDIUM"));
        long openLow = tenantSchemaExecutionService.run(tenant, () -> findingRepository.countByStatusAndSeverity(FindingStatus.OPEN, "LOW"));
        double averageOpenRisk = tenantSchemaExecutionService.run(tenant, () -> findingRepository.averageRiskScoreByTenantAndStatus(tenant, FindingStatus.OPEN));
        double averageOpenConfidence = tenantSchemaExecutionService.run(tenant, () -> findingRepository.averageConfidenceScoreByTenantAndStatus(tenant, FindingStatus.OPEN));
        long highConfidenceOpen = tenantSchemaExecutionService.run(
                tenant,
                () -> findingRepository.countByStatusAndConfidenceScoreGreaterThanEqual(FindingStatus.OPEN, 0.8)
        );
        List<TopFindingMetricResponse> topVulnerabilities = tenantSchemaExecutionService.run(
                tenant,
                () -> findingRepository.findTopVulnerabilitiesByTenantAndStatus(tenant, FindingStatus.OPEN, PageRequest.of(0, 5)));
        List<TopFindingMetricResponse> topInstalledComponents = tenantSchemaExecutionService.run(
                tenant,
                () -> findingRepository.findTopInstalledComponentsByTenantAndStatus(tenant, FindingStatus.OPEN, PageRequest.of(0, 5)));
        List<TopFindingMetricResponse> topAssetsAtRisk = tenantSchemaExecutionService.run(
                tenant,
                () -> findingRepository.findTopAssetsByTenantAndStatus(tenant, FindingStatus.OPEN, PageRequest.of(0, 5)));
        List<TopFindingMetricResponse> topVulnerabilityProductIdentities =
                tenantSchemaExecutionService.run(
                        tenant,
                        () -> findingRepository.findTopVulnerabilityProductIdentitiesByTenantAndStatus(
                                tenant,
                                FindingStatus.OPEN,
                                PageRequest.of(0, 5)));
        List<FindingResponse> latest = findingQueryService.listLatestByTenant(tenant, 10);
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
        long totalItems = componentVulnerabilityStateRepository.countDistinctActiveComponentIdsByTenantAndApplicabilityState(
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
                        row.getAwaitingVexCount(),
                        row.getVexMatchedCount(),
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
        long totalItems = componentVulnerabilityStateRepository.countDistinctActiveVulnerabilityIdsByTenantAndImpactStateIn(
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

        List<ComponentVulnerabilityState> impactedStates = tenantSchemaExecutionService.run(
                tenant,
                () -> componentVulnerabilityStateRepository.findByVulnerability_IdInAndImpactStateIn(
                        requestedIds,
                        FINDING_ELIGIBLE_IMPACT_STATES
                )
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
        Set<UUID> allImpactedComponentIds = new LinkedHashSet<>();
        componentIdsByVulnerability.values().forEach(allImpactedComponentIds::addAll);
        List<InventoryComponentCpeMap> componentCpeMaps = allImpactedComponentIds.isEmpty()
                ? List.of()
                : tenantSchemaExecutionService.run(tenant, () -> inventoryComponentCpeMapRepository.findByComponent_IdIn(allImpactedComponentIds));

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

        Map<UUID, LinkedHashSet<String>> matchedIdentifiersByVulnerability = new HashMap<>();
        for (ComponentVulnerabilityState state : impactedStates) {
            if (state.getVulnerability() == null || state.getVulnerability().getId() == null) {
                continue;
            }
            List<String> identifiers = matchedIdentifiersForState(state, cpesByComponentId);
            if (identifiers.isEmpty()) {
                continue;
            }
            matchedIdentifiersByVulnerability
                    .computeIfAbsent(state.getVulnerability().getId(), ignored -> new LinkedHashSet<>())
                    .addAll(identifiers);
        }

        List<CveInventoryMappingRecordResponse> highRisk = buildCveInventoryMappings(
                highRiskIds,
                aggregatesByVulnerability,
                mappedSoftwareByVulnerability,
                matchedIdentifiersByVulnerability
        );
        List<CveInventoryMappingRecordResponse> latest = buildCveInventoryMappings(
                latestIds,
                aggregatesByVulnerability,
                mappedSoftwareByVulnerability,
                matchedIdentifiersByVulnerability
        );

        return new DashboardCveInventoryMapResponse(highRisk, latest);
    }

    /** Scout Grid exposure narrative: open findings by asset domain x severity.
     *  Rows are seeded from every {@link AssetType} value so the grid is extensible —
     *  a future asset domain appears automatically with zero code changes here. */
    public GridExposureResponse getGridExposure(Tenant tenant) {
        List<Object[]> rows = tenantSchemaExecutionService.run(
                tenant,
                () -> findingRepository.countOpenByAssetTypeAndSeverityForTenant(tenant.getId())
        );

        Map<String, long[]> countsByAssetType = new LinkedHashMap<>();
        for (AssetType type : AssetType.values()) {
            countsByAssetType.put(type.name(), new long[4]);
        }
        for (Object[] row : rows) {
            if (row[0] == null || row[1] == null) {
                continue;
            }
            String assetType = row[0].toString();
            int severityIndex = gridExposureSeverityIndex(row[1].toString());
            if (severityIndex < 0) {
                continue;
            }
            long count = ((Number) row[2]).longValue();
            countsByAssetType.computeIfAbsent(assetType, ignored -> new long[4])[severityIndex] += count;
        }

        List<GridExposureRowResponse> gridRows = new ArrayList<>();
        for (Map.Entry<String, long[]> entry : countsByAssetType.entrySet()) {
            long[] counts = entry.getValue();
            long total = counts[0] + counts[1] + counts[2] + counts[3];
            gridRows.add(new GridExposureRowResponse(entry.getKey(), counts[0], counts[1], counts[2], counts[3], total));
        }
        return new GridExposureResponse(gridRows);
    }

    private static int gridExposureSeverityIndex(String severity) {
        return switch (severity.toUpperCase(Locale.ROOT)) {
            case "CRITICAL" -> 0;
            case "HIGH" -> 1;
            case "MEDIUM" -> 2;
            case "LOW" -> 3;
            default -> -1;
        };
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
            Map<UUID, LinkedHashSet<String>> matchedIdentifiersByVulnerability
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

            List<String> matchedIdentifiers = new ArrayList<>(matchedIdentifiersByVulnerability.getOrDefault(
                    vulnerabilityId,
                    new LinkedHashSet<>()
            ));
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
                    matchedIdentifiers,
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

    private List<String> matchedIdentifiersForState(
            ComponentVulnerabilityState state,
            Map<UUID, Set<String>> cpesByComponentId
    ) {
        if (state == null || state.getComponent() == null || !hasText(state.getMatchedBy())) {
            return List.of();
        }
        String matchedBy = state.getMatchedBy().trim().toLowerCase(Locale.ROOT);
        if (matchedBy.startsWith("cpe-")) {
            UUID componentId = state.getComponent().getId();
            if (componentId == null) {
                return List.of();
            }
            List<String> identifiers = new ArrayList<>(cpesByComponentId.getOrDefault(componentId, Set.of()));
            identifiers.sort(String::compareTo);
            return identifiers;
        }
        if (matchedBy.startsWith("purl-") && hasText(state.getComponent().getPurl())) {
            return List.of(state.getComponent().getPurl().trim());
        }
        if (matchedBy.startsWith("coord-")) {
            String coordKey = componentCoordKey(state);
            return hasText(coordKey) ? List.of(coordKey) : List.of();
        }
        if (matchedBy.startsWith("advisory-pkg-")) {
            String coordKey = componentCoordKey(state);
            return hasText(coordKey) ? List.of("advisory:" + coordKey) : List.of();
        }
        return List.of(matchedBy);
    }

    private String componentCoordKey(ComponentVulnerabilityState state) {
        if (state == null || state.getComponent() == null) {
            return null;
        }
        String ecosystem = IdentityUtil.normalize(state.getComponent().getEcosystem());
        String packageName = IdentityUtil.normalize(state.getComponent().getPackageName());
        if (ecosystem.isBlank() || packageName.isBlank() || "unknown".equals(packageName)) {
            return null;
        }
        return IdentityUtil.coordKey(ecosystem, packageName);
    }

    private DashboardCorrelationEfficiencyResponse buildCorrelationEfficiency(Tenant tenant, long activeComponents) {
        long cpeEligibleActiveComponents = tenantSchemaExecutionService.run(
                tenant,
                () -> inventoryComponentCpeMapRepository.countDistinctComponentIdsByTenantAndComponentStatus(tenant, InventoryComponentStatus.ACTIVE)
        );
        long cpeIneligibleActiveComponents = Math.max(0L, activeComponents - cpeEligibleActiveComponents);
        double cpeCoveragePercent = activeComponents <= 0L
                ? 0.0
                : ((double) cpeEligibleActiveComponents * 100.0) / (double) activeComponents;

        List<Finding> openFindings = tenantSchemaExecutionService.run(
                tenant,
                () -> findingRepository.findByStatusOrderByUpdatedAtDesc(FindingStatus.OPEN)
        );
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
        List<Finding> recentFindings = tenantSchemaExecutionService.run(tenant, () -> findingRepository.findAllByOrderByUpdatedAtDesc()).stream()
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
        DashboardNoiseReductionProjectionService.ProjectionSnapshot projection =
                dashboardNoiseReductionProjectionService.getTenantProjection(tenant);
        long neverOpenedNotApplicable = projection.neverOpenedNotApplicable();
        long deferredUnderInvestigation = projection.deferredUnderInvestigation();
        long autoResolvedNotApplicable = tenantSchemaExecutionService.run(
                tenant,
                () -> findingRepository.countByStatusAndDecisionStateWithEvent(
                        FindingStatus.RESOLVED,
                        FindingDecisionState.NOT_AFFECTED,
                        "AUTO_RESOLVED_NOT_OBSERVED"
                )
        );
        long totalFilteredNotApplicable = neverOpenedNotApplicable + autoResolvedNotApplicable;
        long potentialFindingsWithoutCorrelation = openFindings + totalFilteredNotApplicable;
        double filteredPercentOfPotential = potentialFindingsWithoutCorrelation <= 0
                ? 0
                : (double) totalFilteredNotApplicable * 100.0 / (double) potentialFindingsWithoutCorrelation;

        Map<String, Long> categoryCounts = new HashMap<>(projection.categoryCounts());
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

        long activeVexMatchedStateCount = componentVulnerabilityStateRepository.countActiveStatesWithMatchedVexAssertion(tenant);
        long activeApplicableAwaitingVexCount = componentVulnerabilityStateRepository.countActiveApplicableStatesAwaitingMatchedVexAssertion(tenant);
        long activeVexConfirmedImpactedCount = componentVulnerabilityStateRepository.countActiveStatesByTenantAndImpactState(tenant, ImpactState.IMPACTED);
        long activeVexConfirmedNotAffectedCount = componentVulnerabilityStateRepository.countActiveStatesByTenantAndImpactState(tenant, ImpactState.NOT_IMPACTED);
        long activeVexNoPatchCount = componentVulnerabilityStateRepository.countActiveStatesByTenantAndImpactState(tenant, ImpactState.NO_PATCH);
        double activeVexCoveragePercent = (activeVexMatchedStateCount + activeApplicableAwaitingVexCount) <= 0L
                ? 0.0
                : ((double) activeVexMatchedStateCount * 100.0)
                / (double) (activeVexMatchedStateCount + activeApplicableAwaitingVexCount);

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

        List<Finding> tenantFindings = tenantSchemaExecutionService.run(tenant, () -> findingRepository.findAllByOrderByUpdatedAtDesc());
        Map<String, Long> providerCounts = new HashMap<>();
        long underInvestigationAging = 0L;
        Instant underInvestigationAgingCutoff = now.minusSeconds(14L * 24L * 60L * 60L);
        for (Finding finding : tenantFindings) {
            if (finding == null) {
                continue;
            }
            String vexProvider = finding.getVexProvider();
            if (finding.getStatus() == FindingStatus.OPEN && hasText(vexProvider)) {
                providerCounts.merge(vexProvider, 1L, Long::sum);
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
                activeVexCoveragePercent,
                activeVexMatchedStateCount,
                activeApplicableAwaitingVexCount,
                activeVexConfirmedImpactedCount,
                activeVexConfirmedNotAffectedCount,
                activeVexNoPatchCount,
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
            if (!"STALE".equals(finding.getVexFreshness())) {
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
        List<FindingEvent> events = tenantSchemaExecutionService.run(
                tenant,
                () -> findingEventRepository.findByEventTypeAndCreatedAtGreaterThanEqual(
                        "AUTO_RESOLVED_NOT_OBSERVED",
                        fromInclusive
                )
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
