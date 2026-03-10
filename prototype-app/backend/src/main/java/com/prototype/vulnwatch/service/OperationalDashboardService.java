package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.SbomIngestionStatus;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.DashboardNoiseReductionResponse;
import com.prototype.vulnwatch.dto.DashboardResponse;
import com.prototype.vulnwatch.dto.OperationalApiReadPathResponse;
import com.prototype.vulnwatch.dto.OperationalCorrelationEffectivenessResponse;
import com.prototype.vulnwatch.dto.OperationalDashboardResponse;
import com.prototype.vulnwatch.dto.OperationalEndpointMetricResponse;
import com.prototype.vulnwatch.dto.OperationalExecutiveHealthResponse;
import com.prototype.vulnwatch.dto.OperationalFreshnessDriftResponse;
import com.prototype.vulnwatch.dto.OperationalIngestionEfficiencyResponse;
import com.prototype.vulnwatch.dto.OperationalIngestionSourceMetricResponse;
import com.prototype.vulnwatch.dto.OperationalMetricDefinitionResponse;
import com.prototype.vulnwatch.dto.OperationalNoiseLifecycleResponse;
import com.prototype.vulnwatch.dto.OperationalNormalizationQualityResponse;
import com.prototype.vulnwatch.dto.OperationalSectionResponse;
import com.prototype.vulnwatch.dto.OperationalSourceFreshnessResponse;
import com.prototype.vulnwatch.dto.TopFindingMetricResponse;
import com.prototype.vulnwatch.repo.FindingEventRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.repo.SyncRunRepository;
import com.prototype.vulnwatch.repo.VulnerabilityIntelSummaryRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;

@Service
public class OperationalDashboardService {

    private static final String CVE_PREFIX = "CVE-";
    private static final long HOURS_24 = 24L;
    private static final long HOURS_24_X_7 = HOURS_24 * 7L;
    private static final String AUTO_RESOLVED_EVENT = "AUTO_RESOLVED_NOT_OBSERVED";
    private static final Set<FindingDecisionState> UNKNOWN_STATES =
            EnumSet.of(FindingDecisionState.UNDER_INVESTIGATION, FindingDecisionState.NEEDS_REVIEW);

    private final TenantService tenantService;
    private final DashboardService dashboardService;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final VulnerabilityIntelSummaryRepository vulnerabilityIntelSummaryRepository;
    private final VulnerabilityIntelligenceService vulnerabilityIntelligenceService;
    private final OperationalMetricsService operationalMetricsService;
    private final InventoryComponentRepository inventoryComponentRepository;
    private final FindingRepository findingRepository;
    private final FindingEventRepository findingEventRepository;
    private final SbomUploadRepository sbomUploadRepository;
    private final SyncRunRepository syncRunRepository;

    public OperationalDashboardService(
            TenantService tenantService,
            DashboardService dashboardService,
            VulnerabilityRepository vulnerabilityRepository,
            VulnerabilityIntelSummaryRepository vulnerabilityIntelSummaryRepository,
            VulnerabilityIntelligenceService vulnerabilityIntelligenceService,
            OperationalMetricsService operationalMetricsService,
            InventoryComponentRepository inventoryComponentRepository,
            FindingRepository findingRepository,
            FindingEventRepository findingEventRepository,
            SbomUploadRepository sbomUploadRepository,
            SyncRunRepository syncRunRepository
    ) {
        this.tenantService = tenantService;
        this.dashboardService = dashboardService;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.vulnerabilityIntelSummaryRepository = vulnerabilityIntelSummaryRepository;
        this.vulnerabilityIntelligenceService = vulnerabilityIntelligenceService;
        this.operationalMetricsService = operationalMetricsService;
        this.inventoryComponentRepository = inventoryComponentRepository;
        this.findingRepository = findingRepository;
        this.findingEventRepository = findingEventRepository;
        this.sbomUploadRepository = sbomUploadRepository;
        this.syncRunRepository = syncRunRepository;
    }

    public OperationalDashboardResponse get() {
        Instant now = Instant.now();
        Tenant tenant = tenantService.getDefaultTenant();
        DashboardResponse dashboard = dashboardService.get(tenant);
        DashboardNoiseReductionResponse noise = dashboard.noiseReduction();

        // Time-bounded loads: no full table scans
        Instant sevenDaysAgo = now.minus(Duration.ofHours(HOURS_24_X_7));
        Instant thirtyDaysAgo = now.minus(Duration.ofDays(30));
        List<Finding> findings = findingRepository.findByTenantOrderByUpdatedAtDesc(tenant);
        List<SbomUpload> uploads = sbomUploadRepository
                .findByTenantAndUploadedAtGreaterThanEqualOrderByUploadedAtDesc(tenant, thirtyDaysAgo);
        List<SyncRun> syncRuns = syncRunRepository.findByStartedAtGreaterThanEqual(sevenDaysAgo);
        List<SyncRun> syncRuns24h = syncRuns.stream()
                .filter(run -> run.getStartedAt() != null && run.getStartedAt().isAfter(now.minus(Duration.ofHours(HOURS_24))))
                .toList();
        List<SbomUpload> uploads24h = uploads.stream()
                .filter(upload -> upload.getUploadedAt() != null
                        && upload.getUploadedAt().isAfter(now.minus(Duration.ofHours(HOURS_24))))
                .toList();

        NormalizationStats normalizationStats = buildNormalizationStats(tenant);
        CorrelationStats correlationStats = buildCorrelationStats(findings, now);
        double normalizationCoveragePercent = average(
                normalizationStats.normalizedNameCoveragePercent(),
                normalizationStats.normalizedVersionCoveragePercent(),
                normalizationStats.softwareIdentityCoveragePercent(),
                normalizationStats.softwareModelCoveragePercent()
        );

        OperationalMetricsService.MetricSnapshot recomputeSnapshot =
                operationalMetricsService.snapshot(OperationalMetricsService.KEY_INGESTION_RECOMPUTE_FINDINGS);

        long ingestionAttempts24h = syncRuns24h.size() + uploads24h.size();
        long ingestionSuccesses24h = syncRuns24h.stream()
                .filter(run -> isCompleted(run.getStatus()))
                .count()
                + uploads24h.stream().filter(upload -> upload.getStatus() == SbomIngestionStatus.SUCCESS).count();
        double ingestionSuccessRate24h = percentage(ingestionSuccesses24h, ingestionAttempts24h);

        OperationalExecutiveHealthResponse executiveHealth = new OperationalExecutiveHealthResponse(
                ingestionSuccessRate24h,
                recomputeSnapshot.p95Ms(),
                normalizationCoveragePercent,
                noise.filteredPercentOfPotential(),
                dashboard.openCritical()
        );

        OperationalIngestionEfficiencyResponse ingestionEfficiency = buildIngestionEfficiency(syncRuns24h, uploads24h);
        OperationalNormalizationQualityResponse normalizationQuality = new OperationalNormalizationQualityResponse(
                normalizationStats.activeComponents(),
                normalizationStats.normalizedNameCoveragePercent(),
                normalizationStats.normalizedVersionCoveragePercent(),
                normalizationStats.softwareIdentityCoveragePercent(),
                normalizationStats.softwareModelCoveragePercent(),
                normalizationStats.unresolvedModelCount(),
                normalizationStats.unresolvedModelRatePercent()
        );
        OperationalCorrelationEffectivenessResponse correlationEffectiveness = new OperationalCorrelationEffectivenessResponse(
                correlationStats.openFindings(),
                correlationStats.highConfidenceAffectedRatePercent(),
                correlationStats.unknownDecisionRatePercent(),
                correlationStats.selectedMethodDistribution(),
                correlationStats.decisionStateDistribution(),
                correlationStats.workflowStatusDistribution()
        );
        OperationalNoiseLifecycleResponse noiseLifecycle = new OperationalNoiseLifecycleResponse(
                noise.totalFilteredNotApplicable(),
                noise.neverOpenedNotApplicable(),
                noise.autoResolvedNotApplicable(),
                noise.deferredUnderInvestigation(),
                noise.filteredPercentOfPotential(),
                buildAutoResolvedReopenRate(findings, tenant),
                noise.categories()
        );
        OperationalApiReadPathResponse apiReadPath = buildApiReadPath();
        OperationalFreshnessDriftResponse freshnessDrift = buildFreshnessDrift(
                now,
                tenant,
                findings,
                uploads,
                syncRuns
        );

        return new OperationalDashboardResponse(
                now,
                executiveHealth,
                ingestionEfficiency,
                normalizationQuality,
                correlationEffectiveness,
                noiseLifecycle,
                apiReadPath,
                freshnessDrift,
                metricCatalog()
        );
    }

    public OperationalSectionResponse<OperationalExecutiveHealthResponse> getOverview() {
        OperationalDashboardResponse dashboard = get();
        return new OperationalSectionResponse<>(dashboard.generatedAt(), dashboard.executiveHealth());
    }

    public OperationalSectionResponse<OperationalIngestionEfficiencyResponse> getIngestionEfficiency() {
        OperationalDashboardResponse dashboard = get();
        return new OperationalSectionResponse<>(dashboard.generatedAt(), dashboard.ingestionEfficiency());
    }

    public OperationalSectionResponse<OperationalNormalizationQualityResponse> getNormalizationQuality() {
        OperationalDashboardResponse dashboard = get();
        return new OperationalSectionResponse<>(dashboard.generatedAt(), dashboard.normalizationQuality());
    }

    public OperationalSectionResponse<OperationalCorrelationEffectivenessResponse> getCorrelationEffectiveness() {
        OperationalDashboardResponse dashboard = get();
        return new OperationalSectionResponse<>(dashboard.generatedAt(), dashboard.correlationEffectiveness());
    }

    public OperationalSectionResponse<OperationalNoiseLifecycleResponse> getNoiseLifecycle() {
        OperationalDashboardResponse dashboard = get();
        return new OperationalSectionResponse<>(dashboard.generatedAt(), dashboard.noiseLifecycle());
    }

    public OperationalSectionResponse<OperationalApiReadPathResponse> getApiReadPath() {
        OperationalDashboardResponse dashboard = get();
        return new OperationalSectionResponse<>(dashboard.generatedAt(), dashboard.apiReadPath());
    }

    public OperationalSectionResponse<OperationalFreshnessDriftResponse> getFreshnessDrift() {
        OperationalDashboardResponse dashboard = get();
        return new OperationalSectionResponse<>(dashboard.generatedAt(), dashboard.freshnessDrift());
    }

    public OperationalSectionResponse<List<OperationalMetricDefinitionResponse>> getMetricCatalog() {
        OperationalDashboardResponse dashboard = get();
        return new OperationalSectionResponse<>(dashboard.generatedAt(), dashboard.metricCatalog());
    }

    private OperationalIngestionEfficiencyResponse buildIngestionEfficiency(
            List<SyncRun> syncRuns24h,
            List<SbomUpload> uploads24h
    ) {
        long sbomSuccesses = uploads24h.stream().filter(upload -> upload.getStatus() == SbomIngestionStatus.SUCCESS).count();
        double sbomPerHour = uploads24h.size() / (double) HOURS_24;
        long queueBacklog = syncRunRepository.findQueueByStatuses(List.of("queued", "running")).size();
        long recordsFetched = syncRuns24h.stream().mapToLong(run -> Math.max(0, run.getRecordsFetched())).sum();
        long recordsInserted = syncRuns24h.stream().mapToLong(run -> Math.max(0, run.getRecordsInserted())).sum();
        long recordsUpdated = syncRuns24h.stream().mapToLong(run -> Math.max(0, run.getRecordsUpdated())).sum();

        Map<String, SourceRunStats> sourceStats = new HashMap<>();
        for (SyncRun run : syncRuns24h) {
            String source = normalizeSource(run.getSyncType());
            SourceRunStats stats = sourceStats.computeIfAbsent(source, ignored -> new SourceRunStats());
            stats.runs += 1;
            stats.successes += isCompleted(run.getStatus()) ? 1 : 0;
            stats.failures += isFailed(run.getStatus()) ? 1 : 0;
            stats.fetched += Math.max(0, run.getRecordsFetched());
            stats.inserted += Math.max(0, run.getRecordsInserted());
            stats.updated += Math.max(0, run.getRecordsUpdated());
        }
        if (!uploads24h.isEmpty()) {
            SourceRunStats sbomStats = sourceStats.computeIfAbsent("SBOM_UPLOAD", ignored -> new SourceRunStats());
            sbomStats.runs += uploads24h.size();
            sbomStats.successes += sbomSuccesses;
            sbomStats.failures += uploads24h.stream().filter(upload -> upload.getStatus() == SbomIngestionStatus.FAILURE).count();
            sbomStats.fetched += uploads24h.stream()
                    .map(SbomUpload::getComponentCount)
                    .filter(value -> value != null && value > 0)
                    .mapToLong(Integer::longValue)
                    .sum();
            sbomStats.inserted += uploads24h.stream()
                    .map(SbomUpload::getFindingsGenerated)
                    .filter(value -> value != null && value > 0)
                    .mapToLong(Integer::longValue)
                    .sum();
        }

        List<OperationalIngestionSourceMetricResponse> sourceBreakdown = sourceStats.entrySet().stream()
                .map(entry -> new OperationalIngestionSourceMetricResponse(
                        entry.getKey(),
                        entry.getValue().runs,
                        entry.getValue().successes,
                        entry.getValue().failures,
                        percentage(entry.getValue().successes, entry.getValue().runs),
                        entry.getValue().fetched,
                        entry.getValue().inserted,
                        entry.getValue().updated
                ))
                .sorted(Comparator.comparing(OperationalIngestionSourceMetricResponse::source))
                .toList();

        long syncSuccesses = syncRuns24h.stream().filter(run -> isCompleted(run.getStatus())).count();
        return new OperationalIngestionEfficiencyResponse(
                uploads24h.size(),
                sbomPerHour,
                percentage(sbomSuccesses, uploads24h.size()),
                syncRuns24h.size(),
                percentage(syncSuccesses, syncRuns24h.size()),
                queueBacklog,
                recordsFetched,
                recordsInserted,
                recordsUpdated,
                sourceBreakdown
        );
    }

    private CorrelationStats buildCorrelationStats(List<Finding> findings, Instant now) {
        List<Finding> openFindings = findings.stream()
                .filter(finding -> finding.getStatus() == FindingStatus.OPEN)
                .toList();
        long affectedOpen = openFindings.stream()
                .filter(finding -> finding.getDecisionState() == FindingDecisionState.AFFECTED)
                .count();
        long highConfidenceAffectedOpen = openFindings.stream()
                .filter(finding -> finding.getDecisionState() == FindingDecisionState.AFFECTED)
                .filter(finding -> finding.getConfidenceScore() >= 0.8d)
                .count();
        long unknownOpen = openFindings.stream()
                .filter(finding -> UNKNOWN_STATES.contains(finding.getDecisionState()))
                .count();

        List<TopFindingMetricResponse> selectedMethodDistribution = distribution(
                openFindings.stream().map(Finding::getMatchedBy).toList(),
                12
        );
        List<TopFindingMetricResponse> decisionStateDistribution = distribution(
                openFindings.stream().map(finding -> finding.getDecisionState() == null ? "UNKNOWN" : finding.getDecisionState().name()).toList(),
                10
        );
        List<TopFindingMetricResponse> workflowStatusDistribution = distribution(
                findings.stream().map(finding -> finding.getStatus() == null ? "UNKNOWN" : finding.getStatus().name()).toList(),
                10
        );

        return new CorrelationStats(
                openFindings.size(),
                percentage(highConfidenceAffectedOpen, affectedOpen),
                percentage(unknownOpen, openFindings.size()),
                selectedMethodDistribution,
                decisionStateDistribution,
                workflowStatusDistribution,
                cpeFallbackShare(findings, now.minus(Duration.ofHours(HOURS_24)), now),
                cpeFallbackShare(findings, now.minus(Duration.ofHours(HOURS_24_X_7 + HOURS_24)), now.minus(Duration.ofHours(HOURS_24)))
        );
    }

    private double buildAutoResolvedReopenRate(List<Finding> findings, Tenant tenant) {
        List<UUID> autoResolvedFindingIds = findingEventRepository.findByTenantAndEventTypeSince(
                        tenant,
                        AUTO_RESOLVED_EVENT,
                        Instant.EPOCH
                ).stream()
                .map(event -> event.getFinding() == null ? null : event.getFinding().getId())
                .filter(id -> id != null)
                .distinct()
                .toList();
        if (autoResolvedFindingIds.isEmpty()) {
            return 0.0;
        }
        Map<UUID, FindingStatus> statusByFindingId = new HashMap<>();
        for (Finding finding : findings) {
            statusByFindingId.put(finding.getId(), finding.getStatus());
        }
        long reopened = autoResolvedFindingIds.stream()
                .map(statusByFindingId::get)
                .filter(status -> status == FindingStatus.OPEN)
                .count();
        return percentage(reopened, autoResolvedFindingIds.size());
    }

    private OperationalApiReadPathResponse buildApiReadPath() {
        VulnerabilityIntelligenceService.OperationalState state = vulnerabilityIntelligenceService.getOperationalState();
        long canonicalCveCount = vulnerabilityRepository.countByExternalIdStartingWith(CVE_PREFIX);
        long summaryCveCount = vulnerabilityIntelSummaryRepository.countByExternalIdStartingWith(CVE_PREFIX);
        double summaryCoveragePercent = canonicalCveCount <= 0
                ? 100.0
                : percentage(summaryCveCount, canonicalCveCount);
        long totalFilterCalls = state.filterCacheHits() + state.filterCacheMisses();
        double filterCacheHitRatio = percentage(state.filterCacheHits(), totalFilterCalls);

        List<String> trackedKeys = List.of(
                OperationalMetricsService.KEY_VULN_INTEL_LIST,
                OperationalMetricsService.KEY_VULN_INTEL_FILTERS,
                OperationalMetricsService.KEY_DASHBOARD_OVERVIEW,
                OperationalMetricsService.KEY_OPERATIONS_DASHBOARD,
                OperationalMetricsService.KEY_OPERATIONS_OVERVIEW,
                OperationalMetricsService.KEY_OPERATIONS_INGESTION,
                OperationalMetricsService.KEY_OPERATIONS_NORMALIZATION,
                OperationalMetricsService.KEY_OPERATIONS_CORRELATION,
                OperationalMetricsService.KEY_OPERATIONS_LIFECYCLE,
                OperationalMetricsService.KEY_OPERATIONS_READ_PATH,
                OperationalMetricsService.KEY_OPERATIONS_FRESHNESS,
                OperationalMetricsService.KEY_OPERATIONS_CATALOG,
                OperationalMetricsService.KEY_FINDINGS_LIST,
                OperationalMetricsService.KEY_SBOM_UPLOAD,
                OperationalMetricsService.KEY_SBOM_FETCH_ENDPOINT,
                OperationalMetricsService.KEY_SBOM_FETCH_GITHUB,
                OperationalMetricsService.KEY_INGESTION_NVD_SYNC,
                OperationalMetricsService.KEY_INGESTION_NVD_FULL_SYNC,
                OperationalMetricsService.KEY_INGESTION_KEV_SYNC,
                OperationalMetricsService.KEY_INGESTION_GHSA_SYNC,
                OperationalMetricsService.KEY_INGESTION_CSAF_MICROSOFT_SYNC,
                OperationalMetricsService.KEY_INGESTION_CSAF_REDHAT_SYNC,
                OperationalMetricsService.KEY_INGESTION_ADVISORIES,
                OperationalMetricsService.KEY_INGESTION_RECOMPUTE_FINDINGS
        );
        List<OperationalEndpointMetricResponse> endpointMetrics = trackedKeys.stream()
                .map(operationalMetricsService::snapshot)
                .map(snapshot -> new OperationalEndpointMetricResponse(
                        snapshot.key(),
                        metricLabel(snapshot.key()),
                        snapshot.requestCount(),
                        snapshot.successCount(),
                        snapshot.errorCount(),
                        snapshot.averageMs(),
                        snapshot.p95Ms(),
                        snapshot.p99Ms(),
                        snapshot.maxMs(),
                        snapshot.lastMs(),
                        snapshot.lastRecordedAt()
                ))
                .toList();

        return new OperationalApiReadPathResponse(
                state.summaryReadModelReady(),
                canonicalCveCount,
                summaryCveCount,
                summaryCoveragePercent,
                state.filterCacheActive(),
                state.filterCacheExpiresAt(),
                state.filterCacheHits(),
                state.filterCacheMisses(),
                filterCacheHitRatio,
                endpointMetrics
        );
    }

    private OperationalFreshnessDriftResponse buildFreshnessDrift(
            Instant now,
            Tenant tenant,
            List<Finding> findings,
            List<SbomUpload> uploads,
            List<SyncRun> syncRuns
    ) {
        long staleThresholdHours = HOURS_24;
        Duration staleThreshold = Duration.ofHours(staleThresholdHours);

        Map<String, Instant> latestBySource = new LinkedHashMap<>();
        for (SyncRun run : syncRuns) {
            if (!isCompleted(run.getStatus()) || run.getStartedAt() == null) {
                continue;
            }
            String source = normalizeSource(run.getSyncType());
            latestBySource.merge(source, run.getStartedAt(), (left, right) -> right.isAfter(left) ? right : left);
        }
        uploads.stream()
                .filter(upload -> upload.getStatus() == SbomIngestionStatus.SUCCESS)
                .map(SbomUpload::getUploadedAt)
                .filter(uploadedAt -> uploadedAt != null)
                .max(Comparator.naturalOrder())
                .ifPresent(instant -> latestBySource.put("SBOM_UPLOAD", instant));

        List<OperationalSourceFreshnessResponse> freshness = latestBySource.entrySet().stream()
                .map(entry -> toFreshness(now, staleThreshold, entry.getKey(), entry.getValue()))
                .sorted(Comparator.comparing(OperationalSourceFreshnessResponse::source))
                .toList();
        long staleSourceCount = freshness.stream().filter(OperationalSourceFreshnessResponse::stale).count();

        double currentCoverage = buildNormalizationStats(tenant).overallCoveragePercent();
        double baselineCoverage = buildBaselineNormalizationCoverage(tenant, now.minus(Duration.ofHours(HOURS_24_X_7)));
        if (baselineCoverage == 0.0) {
            baselineCoverage = currentCoverage;
        }

        CorrelationStats correlation = buildCorrelationStats(findings, now);
        return new OperationalFreshnessDriftResponse(
                staleThresholdHours,
                staleSourceCount,
                currentCoverage - baselineCoverage,
                correlation.cpeFallbackShareLast24h() - correlation.cpeFallbackShareBaseline7d(),
                freshness
        );
    }

    private OperationalSourceFreshnessResponse toFreshness(
            Instant now,
            Duration staleThreshold,
            String source,
            Instant lastSuccessfulAt
    ) {
        if (lastSuccessfulAt == null) {
            return new OperationalSourceFreshnessResponse(source, null, -1L, true);
        }
        long ageHours = Math.max(0L, Duration.between(lastSuccessfulAt, now).toHours());
        boolean stale = Duration.between(lastSuccessfulAt, now).compareTo(staleThreshold) > 0;
        return new OperationalSourceFreshnessResponse(source, lastSuccessfulAt, ageHours, stale);
    }

    private NormalizationStats buildNormalizationStats(Tenant tenant) {
        InventoryComponentRepository.NormalizationAggregateRow row =
                inventoryComponentRepository.findNormalizationAggregate(tenant, InventoryComponentStatus.ACTIVE)
                        .orElse(null);
        if (row == null || row.getTotal() == 0) {
            return new NormalizationStats(0, 0, 0, 0, 0, 0, 0);
        }
        long total = row.getTotal();
        long unresolved = row.getUnresolvedCount();
        return new NormalizationStats(
                total,
                unresolved,
                percentage(row.getNormalizedNameCount(), total),
                percentage(row.getNormalizedVersionCount(), total),
                percentage(row.getSoftwareIdentityCount(), total),
                percentage(row.getSoftwareModelCount(), total),
                percentage(unresolved, total)
        );
    }

    private double buildBaselineNormalizationCoverage(Tenant tenant, Instant before) {
        InventoryComponentRepository.NormalizationAggregateRow row =
                inventoryComponentRepository.findNormalizationAggregateBeforeLastObservedAt(
                        tenant, InventoryComponentStatus.ACTIVE, before)
                        .orElse(null);
        if (row == null || row.getTotal() == 0) {
            return 0.0;
        }
        long total = row.getTotal();
        return average(
                percentage(row.getNormalizedNameCount(), total),
                percentage(row.getNormalizedVersionCount(), total),
                percentage(row.getSoftwareIdentityCount(), total),
                percentage(row.getSoftwareModelCount(), total)
        );
    }

    private List<TopFindingMetricResponse> distribution(List<String> values, int limit) {
        Map<String, Long> counts = new HashMap<>();
        for (String value : values) {
            String key = hasText(value) ? value.trim() : "UNKNOWN";
            counts.merge(key, 1L, Long::sum);
        }
        return counts.entrySet().stream()
                .sorted((left, right) -> Long.compare(right.getValue(), left.getValue()))
                .limit(Math.max(1, limit))
                .map(entry -> new TopFindingMetricResponse(entry.getKey(), entry.getValue()))
                .toList();
    }

    private double cpeFallbackShare(List<Finding> findings, Instant fromInclusive, Instant toExclusive) {
        long total = findings.stream()
                .filter(finding -> inRange(finding.getUpdatedAt(), fromInclusive, toExclusive))
                .count();
        if (total <= 0) {
            return 0.0;
        }
        long cpeFallback = findings.stream()
                .filter(finding -> inRange(finding.getUpdatedAt(), fromInclusive, toExclusive))
                .map(Finding::getMatchedBy)
                .filter(this::hasText)
                .map(value -> value.toLowerCase(Locale.ROOT))
                .filter(value -> value.startsWith("cpe-fallback"))
                .count();
        return percentage(cpeFallback, total);
    }

    private boolean inRange(Instant value, Instant fromInclusive, Instant toExclusive) {
        if (value == null) {
            return false;
        }
        if (fromInclusive != null && value.isBefore(fromInclusive)) {
            return false;
        }
        return toExclusive == null || value.isBefore(toExclusive);
    }

    private boolean isCompleted(String status) {
        return hasText(status) && "completed".equalsIgnoreCase(status.trim());
    }

    private boolean isFailed(String status) {
        return hasText(status) && "failed".equalsIgnoreCase(status.trim());
    }

    private String normalizeSource(String value) {
        if (!hasText(value)) {
            return "UNKNOWN";
        }
        return value.trim().toUpperCase(Locale.ROOT).replace(' ', '_');
    }

    private double percentage(long numerator, long denominator) {
        if (denominator <= 0) {
            return 0.0;
        }
        return (double) numerator * 100.0 / (double) denominator;
    }

    private double average(double... values) {
        if (values == null || values.length == 0) {
            return 0.0;
        }
        double total = 0.0;
        for (double value : values) {
            total += value;
        }
        return total / (double) values.length;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private String metricLabel(String key) {
        return switch (key) {
            case OperationalMetricsService.KEY_VULN_INTEL_LIST -> "Vulnerability Intelligence List";
            case OperationalMetricsService.KEY_VULN_INTEL_FILTERS -> "Vulnerability Intelligence Filters";
            case OperationalMetricsService.KEY_DASHBOARD_OVERVIEW -> "Overview Dashboard";
            case OperationalMetricsService.KEY_OPERATIONS_DASHBOARD -> "Operations Dashboard";
            case OperationalMetricsService.KEY_OPERATIONS_OVERVIEW -> "Operations Overview";
            case OperationalMetricsService.KEY_OPERATIONS_INGESTION -> "Operations Ingestion Efficiency";
            case OperationalMetricsService.KEY_OPERATIONS_NORMALIZATION -> "Operations Normalization Quality";
            case OperationalMetricsService.KEY_OPERATIONS_CORRELATION -> "Operations Correlation Effectiveness";
            case OperationalMetricsService.KEY_OPERATIONS_LIFECYCLE -> "Operations Noise & Lifecycle";
            case OperationalMetricsService.KEY_OPERATIONS_READ_PATH -> "Operations API Read-Path";
            case OperationalMetricsService.KEY_OPERATIONS_FRESHNESS -> "Operations Freshness & Drift";
            case OperationalMetricsService.KEY_OPERATIONS_CATALOG -> "Operations Metric Catalog";
            case OperationalMetricsService.KEY_FINDINGS_LIST -> "Findings List";
            case OperationalMetricsService.KEY_SBOM_UPLOAD -> "SBOM Upload";
            case OperationalMetricsService.KEY_SBOM_FETCH_ENDPOINT -> "SBOM Fetch Endpoint";
            case OperationalMetricsService.KEY_SBOM_FETCH_GITHUB -> "SBOM Fetch GitHub";
            case OperationalMetricsService.KEY_INGESTION_NVD_SYNC -> "NVD Sync Trigger";
            case OperationalMetricsService.KEY_INGESTION_NVD_FULL_SYNC -> "NVD Full Sync Trigger";
            case OperationalMetricsService.KEY_INGESTION_KEV_SYNC -> "KEV Sync Trigger";
            case OperationalMetricsService.KEY_INGESTION_GHSA_SYNC -> "GHSA Sync Trigger";
            case OperationalMetricsService.KEY_INGESTION_CSAF_MICROSOFT_SYNC -> "CSAF Microsoft Sync Trigger";
            case OperationalMetricsService.KEY_INGESTION_CSAF_REDHAT_SYNC -> "CSAF Red Hat Sync Trigger";
            case OperationalMetricsService.KEY_INGESTION_ADVISORIES -> "Advisory Ingest Trigger";
            case OperationalMetricsService.KEY_INGESTION_RECOMPUTE_FINDINGS -> "Recompute Findings Trigger";
            default -> key;
        };
    }

    private List<OperationalMetricDefinitionResponse> metricCatalog() {
        List<OperationalMetricDefinitionResponse> metrics = new ArrayList<>();
        metrics.add(new OperationalMetricDefinitionResponse(
                "Executive Health",
                "ingestion.success_rate_24h",
                "Ingestion Success Rate (24h)",
                "Successful ingestion runs and uploads divided by all ingestion attempts in the last 24 hours."
        ));
        metrics.add(new OperationalMetricDefinitionResponse(
                "Executive Health",
                "correlation.recompute_p95_ms",
                "Recompute Trigger P95 (ms)",
                "P95 API latency for the manual recompute trigger endpoint."
        ));
        metrics.add(new OperationalMetricDefinitionResponse(
                "Executive Health",
                "normalization.coverage_composite",
                "Normalization Coverage Composite",
                "Average of normalized name, normalized version, software identity, and software model coverage."
        ));
        metrics.add(new OperationalMetricDefinitionResponse(
                "Ingestion Efficiency",
                "ingestion.sbom_per_hour",
                "SBOM Ingestions Per Hour",
                "SBOM ingestions during the last 24 hours divided by 24."
        ));
        metrics.add(new OperationalMetricDefinitionResponse(
                "Ingestion Efficiency",
                "ingestion.sync_records_24h",
                "Sync Records Processed (24h)",
                "Total records fetched, inserted, and updated from sync runs in the last 24 hours."
        ));
        metrics.add(new OperationalMetricDefinitionResponse(
                "Normalization Quality",
                "normalization.normalized_name_coverage",
                "Normalized Name Coverage",
                "Share of active components with a normalized name value."
        ));
        metrics.add(new OperationalMetricDefinitionResponse(
                "Normalization Quality",
                "normalization.software_identity_coverage",
                "Software Identity Coverage",
                "Share of active components linked to a software identity."
        ));
        metrics.add(new OperationalMetricDefinitionResponse(
                "Correlation Effectiveness",
                "correlation.high_confidence_affected_rate",
                "High Confidence Affected Rate",
                "Affected open findings with confidence >= 0.80 divided by all affected open findings."
        ));
        metrics.add(new OperationalMetricDefinitionResponse(
                "Correlation Effectiveness",
                "correlation.unknown_decision_rate",
                "Unknown Decision Rate",
                "Open findings in under-investigation or needs-review states divided by all open findings."
        ));
        metrics.add(new OperationalMetricDefinitionResponse(
                "Noise & Lifecycle",
                "noise.filtered_percent",
                "Filtered Percent of Potential",
                "Not-applicable findings filtered by correlation divided by potential findings."
        ));
        metrics.add(new OperationalMetricDefinitionResponse(
                "Noise & Lifecycle",
                "noise.reopen_rate_after_auto_resolve",
                "Reopen Rate After Auto Resolve",
                "Findings currently reopened among findings that were auto-resolved for not observed."
        ));
        metrics.add(new OperationalMetricDefinitionResponse(
                "API & Read-Path",
                "api.endpoint_latency",
                "Endpoint Latency (Avg/P95/P99)",
                "Per-endpoint API latency and error counts for operationally relevant routes."
        ));
        metrics.add(new OperationalMetricDefinitionResponse(
                "Data Freshness & Drift",
                "freshness.stale_source_count",
                "Stale Source Count",
                "Number of ingestion sources without a successful run within the stale threshold."
        ));
        metrics.add(new OperationalMetricDefinitionResponse(
                "Data Freshness & Drift",
                "drift.cpe_fallback_share_7d",
                "CPE Fallback Share Drift",
                "Difference between last-24h and baseline-window share of cpe-fallback selected matches."
        ));
        return metrics;
    }

    private static final class SourceRunStats {
        private long runs;
        private long successes;
        private long failures;
        private long fetched;
        private long inserted;
        private long updated;
    }

    private record NormalizationStats(
            long activeComponents,
            long unresolvedModelCount,
            double normalizedNameCoveragePercent,
            double normalizedVersionCoveragePercent,
            double softwareIdentityCoveragePercent,
            double softwareModelCoveragePercent,
            double unresolvedModelRatePercent
    ) {
        double overallCoveragePercent() {
            return (normalizedNameCoveragePercent + normalizedVersionCoveragePercent + softwareIdentityCoveragePercent
                    + softwareModelCoveragePercent) / 4.0;
        }
    }

    private record CorrelationStats(
            long openFindings,
            double highConfidenceAffectedRatePercent,
            double unknownDecisionRatePercent,
            List<TopFindingMetricResponse> selectedMethodDistribution,
            List<TopFindingMetricResponse> decisionStateDistribution,
            List<TopFindingMetricResponse> workflowStatusDistribution,
            double cpeFallbackShareLast24h,
            double cpeFallbackShareBaseline7d
    ) {
    }
}
