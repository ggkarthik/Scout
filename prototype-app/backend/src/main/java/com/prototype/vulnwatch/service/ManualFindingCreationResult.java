package com.prototype.vulnwatch.service;

public record ManualFindingCreationResult(
        int eligibleComponentCount,
        int createdCount,
        int reopenedCount,
        int alreadyOpenCount
) {
}
