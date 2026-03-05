package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;

public record OperationalDashboardResponse(
        Instant generatedAt,
        OperationalExecutiveHealthResponse executiveHealth,
        OperationalIngestionEfficiencyResponse ingestionEfficiency,
        OperationalNormalizationQualityResponse normalizationQuality,
        OperationalCorrelationEffectivenessResponse correlationEffectiveness,
        OperationalNoiseLifecycleResponse noiseLifecycle,
        OperationalApiReadPathResponse apiReadPath,
        OperationalFreshnessDriftResponse freshnessDrift,
        List<OperationalMetricDefinitionResponse> metricCatalog
) {
}
