package com.prototype.vulnwatch.dto;

import java.util.List;

public record CreateServiceNowIncidentRequest(
        String findingTitle,
        String severity,
        Double cvssScore,
        Double epssScore,
        boolean inKev,
        String priority,
        String dueDate,
        String assignedTo,
        String notes,
        /** Patch / fix version info and remediation guidance, placed in resolution_notes */
        String solutionInfo,
        /** Due date (YYYY-MM-DD) for creating a Task SLA remediation target in ServiceNow */
        String taskSlaDueDate,
        List<AffectedAsset> affectedAssets
) {
    public record AffectedAsset(
            String componentId,
            String assetName,
            String assetIdentifier,
            String assetType,
            String packageName,
            String packageVersion,
            /** Per-asset assignment group (from supportGroup / CMDB ownership) */
            String assignmentGroup
    ) {}
}
