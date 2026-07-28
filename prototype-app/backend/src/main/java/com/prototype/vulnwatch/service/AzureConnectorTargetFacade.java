package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.AzureDiscoveryTarget;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.AzureDiscoveryTargetRepository;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;

@Service
public class AzureConnectorTargetFacade {

    private final AzureDiscoveryTargetRepository targets;
    private final TenantSchemaExecutionService tenantExecution;

    public AzureConnectorTargetFacade(
            AzureDiscoveryTargetRepository targets,
            TenantSchemaExecutionService tenantExecution
    ) {
        this.targets = targets;
        this.tenantExecution = tenantExecution;
    }

    public TargetSnapshot require(Tenant tenant, UUID targetId) {
        if (tenant == null || tenant.getId() == null || targetId == null) {
            throw new IllegalArgumentException("Azure connector target is required");
        }
        return tenantExecution.run(tenant, () -> {
            AzureDiscoveryTarget target = targets.findByIdAndTenant_Id(targetId, tenant.getId())
                    .orElseThrow(() -> new IllegalArgumentException("Azure connector target not found"));
            return snapshot(target);
        });
    }

    public List<TargetSnapshot> list(Tenant tenant) {
        if (tenant == null || tenant.getId() == null) {
            return List.of();
        }
        return tenantExecution.run(tenant, () -> targets.findAll().stream()
                .filter(target -> target.getTenant() != null && tenant.getId().equals(target.getTenant().getId()))
                .map(this::snapshot).toList());
    }

    private TargetSnapshot snapshot(AzureDiscoveryTarget target) {
        return new TargetSnapshot(
                target.getId(),
                target.getConfig().getId(),
                target.getSubscriptionId(),
                target.getSubscriptionName(),
                target.getRegionsJson(),
                target.isEnabled());
    }

    public record TargetSnapshot(
            UUID targetId,
            UUID configId,
            String subscriptionId,
            String subscriptionName,
            String regionsJson,
            boolean enabled
    ) {
    }
}
