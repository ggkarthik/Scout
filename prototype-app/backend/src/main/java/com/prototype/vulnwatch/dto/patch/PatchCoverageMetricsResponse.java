package com.prototype.vulnwatch.dto.patch;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PatchCoverageMetricsResponse {
    private long totalPatches;
    private long deployedPatches;
    private long pendingPatches;
    private long failedPatches;
    private double deploymentPercentage;
    private Map<String, Long> byEcosystem;
    private Map<String, Long> bySeverity;
    private Map<String, Long> byDeploymentStatus;
    private List<PatchCoverageBySourceSystem> bySourceSystem;

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class PatchCoverageBySourceSystem {
        private String sourceSystem;
        private long totalPatches;
        private long deployedPatches;
        private double deploymentPercentage;
    }
}
