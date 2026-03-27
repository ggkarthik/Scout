package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.OperationalDashboardResponse;
import com.prototype.vulnwatch.dto.OperationalSectionResponse;
import com.prototype.vulnwatch.dto.OperationalApiReadPathResponse;
import com.prototype.vulnwatch.dto.OperationalCorrelationEffectivenessResponse;
import com.prototype.vulnwatch.dto.OperationalExecutiveHealthResponse;
import com.prototype.vulnwatch.dto.OperationalFreshnessDriftResponse;
import com.prototype.vulnwatch.dto.OperationalIngestionEfficiencyResponse;
import com.prototype.vulnwatch.dto.OperationalMetricDefinitionResponse;
import com.prototype.vulnwatch.dto.OperationalNoiseLifecycleResponse;
import com.prototype.vulnwatch.dto.OperationalNormalizationQualityResponse;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.OperationalQualityFilterValuesResponse;
import com.prototype.vulnwatch.dto.OperationalQualityIssueDetailResponse;
import com.prototype.vulnwatch.dto.OperationalQualityIssuePageResponse;
import com.prototype.vulnwatch.dto.OperationalQualitySummaryResponse;
import com.prototype.vulnwatch.service.OperationalDashboardService;
import com.prototype.vulnwatch.service.OperationalQualityReadService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.util.List;
import java.util.UUID;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/operations")
public class OperationalDashboardController {

    private final OperationalDashboardService operationalDashboardService;
    private final WorkspaceService workspaceService;
    private final OperationalQualityReadService operationalQualityReadService;

    public OperationalDashboardController(
            OperationalDashboardService operationalDashboardService,
            WorkspaceService workspaceService,
            OperationalQualityReadService operationalQualityReadService
    ) {
        this.operationalDashboardService = operationalDashboardService;
        this.workspaceService = workspaceService;
        this.operationalQualityReadService = operationalQualityReadService;
    }

    @GetMapping("/dashboard")
    public OperationalDashboardResponse get() {
        return operationalDashboardService.get();
    }

    @GetMapping("/overview")
    public OperationalSectionResponse<OperationalExecutiveHealthResponse> getOverview() {
        return operationalDashboardService.getOverview();
    }

    @GetMapping("/ingestion-efficiency")
    public OperationalSectionResponse<OperationalIngestionEfficiencyResponse> getIngestionEfficiency() {
        return operationalDashboardService.getIngestionEfficiency();
    }

    @GetMapping("/normalization-quality")
    public OperationalSectionResponse<OperationalNormalizationQualityResponse> getNormalizationQuality() {
        return operationalDashboardService.getNormalizationQuality();
    }

    @GetMapping("/correlation-effectiveness")
    public OperationalSectionResponse<OperationalCorrelationEffectivenessResponse> getCorrelationEffectiveness() {
        return operationalDashboardService.getCorrelationEffectiveness();
    }

    @GetMapping("/noise-lifecycle")
    public OperationalSectionResponse<OperationalNoiseLifecycleResponse> getNoiseLifecycle() {
        return operationalDashboardService.getNoiseLifecycle();
    }

    @GetMapping("/api-read-path")
    public OperationalSectionResponse<OperationalApiReadPathResponse> getApiReadPath() {
        return operationalDashboardService.getApiReadPath();
    }

    @GetMapping("/freshness-drift")
    public OperationalSectionResponse<OperationalFreshnessDriftResponse> getFreshnessDrift() {
        return operationalDashboardService.getFreshnessDrift();
    }

    @GetMapping("/metric-catalog")
    public OperationalSectionResponse<List<OperationalMetricDefinitionResponse>> getMetricCatalog() {
        return operationalDashboardService.getMetricCatalog();
    }

    @GetMapping("/quality/summary")
    public OperationalQualitySummaryResponse getQualitySummary() {
        return operationalQualityReadService.getSummary(defaultTenant());
    }

    @GetMapping("/quality/issues")
    public OperationalQualityIssuePageResponse listQualityIssues(
            @RequestParam(required = false) String domain,
            @RequestParam(required = false) String issueType,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) Boolean affectsActiveFindings,
            @RequestParam(required = false) List<AssetType> assetType,
            @RequestParam(required = false) List<String> sourceSystem,
            @RequestParam(required = false) List<String> ecosystem,
            @RequestParam(required = false) String query,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "25") int size
    ) {
        return operationalQualityReadService.listIssues(
                defaultTenant(),
                domain,
                issueType,
                severity,
                affectsActiveFindings,
                assetType,
                sourceSystem,
                ecosystem,
                query,
                page,
                size
        );
    }

    @GetMapping("/quality/issues/{issueId}")
    public OperationalQualityIssueDetailResponse getQualityIssue(@PathVariable String issueId) {
        return operationalQualityReadService.getIssueDetail(defaultTenant(), issueId);
    }

    @GetMapping("/quality/filters")
    public OperationalQualityFilterValuesResponse getQualityFilters() {
        return operationalQualityReadService.listFilterValues(defaultTenant());
    }

    private Tenant defaultTenant() {
        return workspaceService.getWorkspace();
    }
}
