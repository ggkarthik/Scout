package com.prototype.vulnwatch.dto;

import java.util.UUID;

/**
 * A declared AI-BOM resource (model/dataset) a {@code VULNERABILITY} finding transitively
 * affects, per {@code ai_bom_resource_vulnerability_links}. Batch-loaded for an already
 * paginated page of findings -- never joined into the findings query itself, since a finding
 * can be reached by more than one declared resource and a join would multiply rows ahead of
 * pagination.
 */
public record AffectedAiResourceSummary(UUID id, String name, String resourceKind) {
}
