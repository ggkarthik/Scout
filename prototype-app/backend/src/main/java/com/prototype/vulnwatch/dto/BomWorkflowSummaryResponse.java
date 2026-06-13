package com.prototype.vulnwatch.dto;

public record BomWorkflowSummaryResponse(
        String workflowStatus,
        long componentCount
) {}
