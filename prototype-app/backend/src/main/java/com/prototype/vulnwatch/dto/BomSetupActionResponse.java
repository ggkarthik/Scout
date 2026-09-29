package com.prototype.vulnwatch.dto;

import java.util.UUID;

/**
 * Coverage work an AI-BOM pipeline needs a person to resolve -- an unlinked or ambiguous
 * declaration, or a source held behind entitlement/backlog. Deliberately never surfaced as a
 * {@code Finding}: none of this is a policy violation, it's setup work still in progress.
 */
public record BomSetupActionResponse(
        String category,
        String priority,
        String title,
        String detail,
        UUID evidenceId
) {
}
