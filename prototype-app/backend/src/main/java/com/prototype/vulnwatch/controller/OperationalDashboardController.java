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
import com.prototype.vulnwatch.service.OperationalDashboardService;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/operations")
public class OperationalDashboardController {

    private final OperationalDashboardService operationalDashboardService;

    public OperationalDashboardController(OperationalDashboardService operationalDashboardService) {
        this.operationalDashboardService = operationalDashboardService;
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
}
