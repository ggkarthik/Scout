package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.AssetResponse;
import com.prototype.vulnwatch.repo.AssetRepository;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class AssetQueryService {

    private final AssetRepository assetRepository;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;

    public AssetQueryService(
            AssetRepository assetRepository,
            TenantSchemaExecutionService tenantSchemaExecutionService
    ) {
        this.assetRepository = assetRepository;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
    }

    public List<AssetResponse> listAssets(Tenant tenant) {
        return tenantSchemaExecutionService.run(tenant, assetRepository::findAllByOrderByNameAsc).stream()
                .map(asset -> new AssetResponse(
                        asset.getId(),
                        asset.getType().name(),
                        asset.getName(),
                        asset.getIdentifier(),
                        asset.getServiceName(),
                        asset.getEnvironment(),
                        asset.getOwnerTeam(),
                        asset.getOwnerEmail(),
                        asset.getBusinessCriticality().name(),
                        asset.getState().name(),
                        asset.getLastInventoryAt(),
                        asset.getLastCmdbSyncAt()))
                .toList();
    }

    public List<String> listAssignmentGroups(Tenant tenant) {
        return tenantSchemaExecutionService.run(tenant, assetRepository::findDistinctSupportGroups);
    }

    public List<String> listAssignedTo(Tenant tenant) {
        return tenantSchemaExecutionService.run(tenant, assetRepository::findDistinctAssignedTo);
    }
}
