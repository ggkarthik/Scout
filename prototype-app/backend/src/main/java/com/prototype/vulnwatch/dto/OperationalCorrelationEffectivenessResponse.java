package com.prototype.vulnwatch.dto;

import java.util.List;

public record OperationalCorrelationEffectivenessResponse(
        long openFindings,
        double highConfidenceAffectedRatePercent,
        double unknownDecisionRatePercent,
        List<TopFindingMetricResponse> selectedMethodDistribution,
        List<TopFindingMetricResponse> decisionStateDistribution,
        List<TopFindingMetricResponse> workflowStatusDistribution
) {
}
