package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.AssetFixStatus;
import com.prototype.vulnwatch.domain.Fix;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.repo.AssetFixStatusRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class FixApplicabilityService {

    private final AssetFixStatusRepository assetFixStatusRepository;

    public FixApplicabilityDecision evaluate(
        InventoryComponent component,
        List<Fix> applicableFixes,
        UUID tenantId) {

        if (component == null || component.getAsset() == null || applicableFixes.isEmpty()) {
            return new FixApplicabilityDecision(false, "no_fixes", null, null);
        }

        // Check deployment status for best matching fix
        for (Fix fix : applicableFixes) {
            AssetFixStatus status = assetFixStatusRepository
                .findByTenantAndAssetAndFix(tenantId, component.getAsset().getId(), fix.getId())
                .orElse(null);

            if (status != null) {
                // Return decision based on deployment status
                return new FixApplicabilityDecision(
                    status.getDeploymentStatus() != AssetFixStatus.DeploymentStatus.DEPLOYED,
                    "fix_deployment_status_" + status.getDeploymentStatus().name().toLowerCase(),
                    status.getDeploymentStatus(),
                    "KB_DEPLOYMENT"
                );
            }
        }

        // No deployment record - assume not deployed (vulnerable)
        return new FixApplicabilityDecision(
            true,
            "fix_not_deployed",
            AssetFixStatus.DeploymentStatus.PENDING,
            "VERSION_ONLY"
        );
    }

    public record FixApplicabilityDecision(
        boolean affected,
        String reason,
        AssetFixStatus.DeploymentStatus deploymentStatus,
        String confidenceSource
    ) {
        public boolean isAffected() {
            return affected;
        }

        public boolean isDeployed() {
            return deploymentStatus == AssetFixStatus.DeploymentStatus.DEPLOYED;
        }

        public String getDeploymentStatus() {
            return deploymentStatus != null ? deploymentStatus.name() : "UNKNOWN";
        }

        public String getConfidenceSource() {
            return confidenceSource != null ? confidenceSource : "UNKNOWN";
        }
    }
}
