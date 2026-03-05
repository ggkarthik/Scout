package com.prototype.vulnwatch.dto;

public record FindingBulkWorkflowResponse(
        int targeted,
        int updated,
        int failed,
        String message
) {
}
