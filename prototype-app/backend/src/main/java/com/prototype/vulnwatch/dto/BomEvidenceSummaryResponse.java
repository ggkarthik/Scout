package com.prototype.vulnwatch.dto;

import java.util.List;

public record BomEvidenceSummaryResponse(
        long documentCount,
        long componentCount,
        long evidenceCount,
        long vulnerabilityLinkCount,
        long componentsInWorkflow,
        List<BomEvidenceDocumentResponse> documents,
        List<BomEvidenceComponentResponse> components
) {
}
