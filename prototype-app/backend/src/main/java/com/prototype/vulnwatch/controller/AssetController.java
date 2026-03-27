package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.AssetResponse;
import com.prototype.vulnwatch.dto.CmdbAssetSyncRequest;
import com.prototype.vulnwatch.dto.CmdbAssetSyncResponse;
import com.prototype.vulnwatch.dto.HostAssetDetailResponse;
import com.prototype.vulnwatch.service.AssetQueryService;
import com.prototype.vulnwatch.service.AssetLifecycleService;
import com.prototype.vulnwatch.service.HostInventoryReadService;
import com.prototype.vulnwatch.service.WorkspaceService;
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

    private final WorkspaceService workspaceService;
    private final AssetQueryService assetQueryService;
    private final AssetLifecycleService assetLifecycleService;
    private final HostInventoryReadService hostInventoryReadService;

    public AssetController(
            WorkspaceService workspaceService,
            AssetQueryService assetQueryService,
            AssetLifecycleService assetLifecycleService,
            HostInventoryReadService hostInventoryReadService
    ) {
        this.workspaceService = workspaceService;
        this.assetQueryService = assetQueryService;
        this.assetLifecycleService = assetLifecycleService;
        this.hostInventoryReadService = hostInventoryReadService;
    }

    @GetMapping
    public List<AssetResponse> list() {
        Tenant tenant = workspaceService.getWorkspace();
        return assetQueryService.listAssets(tenant);
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
        Tenant tenant = workspaceService.getWorkspace();
        return hostInventoryReadService.getHostDetail(tenant, assetId, sourceSystem);
    }
}
