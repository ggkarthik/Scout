package com.prototype.vulnwatch.dto.patch;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

/**
 * Complete dashboard response combining metrics and statistics
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PatchDeploymentDashboardResponse {

    // Coverage metrics section
    private CoverageMetrics coverage;

    // Auto-resolution statistics section
    private AutoResolutionStats autoResolution;

    // Health scoring section
    private HealthScore health;

    // Top patches section
    private List<PatchSummary> topPatches;

    // Recent activity section
    private List<RecentActivity> recentActivity;

    // Recommendations section
    private List<String> recommendations;

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class CoverageMetrics {
        private long totalPatches;
        private long deployedPatches;
        private long pendingPatches;
        private long failedPatches;
        private double deploymentPercentage;
        private Map<String, Long> byEcosystem;
        private Map<String, Long> bySeverity;
        private List<SourceSystemMetrics> bySourceSystem;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class SourceSystemMetrics {
        private String sourceSystem;
        private long totalPatches;
        private long deployedPatches;
        private double deploymentPercentage;
        private long lastSyncSeconds;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class AutoResolutionStats {
        private long totalAutoResolved;
        private long uniqueCvesResolved;
        private long findingsResolvedThisWeek;
        private double averageResolutionTimeHours;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class HealthScore {
        private String status;  // EXCELLENT, GOOD, FAIR, POOR
        private int score;  // 0-100
        private String recommendation;
        private List<String> warnings;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class PatchSummary {
        private String fixId;
        private String title;
        private String sourceSystem;
        private String severity;
        private int applicableAssets;
        private int deployedAssets;
        private double deploymentPercentage;
        private String ecosystem;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class RecentActivity {
        private String type;  // DEPLOYED, FAILED, AUTO_RESOLVED, INGESTION
        private String description;
        private long timestampSeconds;
        private Map<String, String> metadata;
    }
}
