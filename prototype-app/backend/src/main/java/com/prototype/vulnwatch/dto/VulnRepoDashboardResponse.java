package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;

public record VulnRepoDashboardResponse(
        Instant generatedAt,
        SummaryCards summaryCards,
        List<SeverityBreakdownItem> severityBreakdown,
        ResolutionStatus resolutionStatus,
        List<CriticalUnresolvedItem> criticalUnresolved,
        List<TopAffectedSoftwareItem> topAffectedSoftware,
        List<RecentAdvisoryItem> recentAdvisories,
        List<ImpactedAssetItem> impactedAssets
) {
    public record SummaryCards(
            long trackedCount,
            long trackedAddedLastWeek,
            long applicableCount,
            long applicableAddedLastWeek,
            long impactedInvestigationDoneCount,
            long impactedAddedLastWeek,
            long remediationCveCount,
            long needsAttentionCount,
            long criticalCount,
            long exploitCount,
            int exploitCoveragePercent
    ) {
    }

    public record SeverityBreakdownItem(
            String severity,
            long count
    ) {
    }

    public record ResolutionStatus(
            long unresolvedCount,
            long resolvedCount,
            long inProgressCount,
            long acceptedRiskCount
    ) {
    }

    public record CriticalUnresolvedItem(
            String externalId,
            String title,
            String severity,
            String statusLabel,
            boolean exploitKnown,
            long findingCount
    ) {
    }

    public record TopAffectedSoftwareItem(
            String softwareIdentityId,
            String software,
            String vendor,
            long cveCount,
            long criticalCount,
            long highCount,
            long impactedAssetCount,
            String highestSeverity
    ) {
    }

    public record RecentAdvisoryItem(
            String externalId,
            String title,
            String descriptionSnippet,
            String severity,
            String source,
            Instant publishedAt,
            Instant lastModifiedAt
    ) {
    }

    public record ImpactedAssetItem(
            String assetId,
            String assetName,
            String assetType,
            String identifier,
            String environment,
            long cveCount
    ) {
    }
}
