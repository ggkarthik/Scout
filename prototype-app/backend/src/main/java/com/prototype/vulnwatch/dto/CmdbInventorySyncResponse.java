package com.prototype.vulnwatch.dto;

public record CmdbInventorySyncResponse(
        String sourceSystem,
        int installRowsProcessed,
        int discoveryRowsProcessed,
        int unmatchedDiscoveryRows,
        int assetsIngested,
        int ciCreated,
        int ciAliasesCreated,
        int softwareInstancesCreated,
        int softwareInstancesUpdated,
        int inventoryComponentsCreated,
        int inventoryComponentsUpdated,
        int findingsRecomputed,
        String message
) {
}
