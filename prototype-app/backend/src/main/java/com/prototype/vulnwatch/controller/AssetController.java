package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.AssetResponse;
import com.prototype.vulnwatch.dto.CmdbAssetSyncRequest;
import com.prototype.vulnwatch.dto.CmdbAssetSyncResponse;
import com.prototype.vulnwatch.dto.HostAssetDetailResponse;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.service.AssetLifecycleService;
import com.prototype.vulnwatch.service.HostInventoryReadService;
import com.prototype.vulnwatch.service.TenantService;
import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/assets")
public class AssetController {

    private final TenantService tenantService;
    private final AssetRepository assetRepository;
    private final AssetLifecycleService assetLifecycleService;
    private final HostInventoryReadService hostInventoryReadService;

    public AssetController(
            TenantService tenantService,
            AssetRepository assetRepository,
            AssetLifecycleService assetLifecycleService,
            HostInventoryReadService hostInventoryReadService
    ) {
        this.tenantService = tenantService;
        this.assetRepository = assetRepository;
        this.assetLifecycleService = assetLifecycleService;
        this.hostInventoryReadService = hostInventoryReadService;
    }

    @GetMapping
    public List<AssetResponse> list() {
        Tenant tenant = tenantService.getDefaultTenant();
        return assetRepository.findByTenant(tenant).stream()
                .map(a -> new AssetResponse(
                        a.getId(),
                        a.getType().name(),
                        a.getName(),
                        a.getIdentifier(),
                        a.getServiceName(),
                        a.getEnvironment(),
                        a.getOwnerTeam(),
                        a.getOwnerEmail(),
                        a.getBusinessCriticality().name(),
                        a.getState().name(),
                        a.getLastInventoryAt(),
                        a.getLastCmdbSyncAt()))
                .toList();
    }

    @PostMapping("/cmdb-sync")
    public CmdbAssetSyncResponse cmdbSync(@Valid @RequestBody CmdbAssetSyncRequest request) {
        return assetLifecycleService.syncFromCmdb(request);
    }

    @GetMapping("/hosts/{assetId:[0-9a-fA-F\\-]{36}}")
    public HostAssetDetailResponse hostDetail(
            @PathVariable UUID assetId,
            @RequestParam(name = "sourceSystem", required = false) String sourceSystem
    ) {
        Tenant tenant = tenantService.getDefaultTenant();
        return hostInventoryReadService.getHostDetail(tenant, assetId, sourceSystem);
    }
}
