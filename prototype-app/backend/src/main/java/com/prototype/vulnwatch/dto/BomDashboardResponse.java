package com.prototype.vulnwatch.dto;

import java.util.List;

public record BomDashboardResponse(
        long documentCount,
        long componentCount,
        long evidenceCount,
        long vulnerabilityLinkCount,
        long correlatedComponentCount,
        long activeWorkflowCount,
        long openRemediationCount,
        long sourceSystemCount,
        List<BomDashboardBreakdownItemResponse> bomTypes,
        List<BomDashboardBreakdownItemResponse> specFamilies,
        List<BomDashboardBreakdownItemResponse> sourceSystems,
        List<BomDashboardBreakdownItemResponse> workflowStatuses
) {}
