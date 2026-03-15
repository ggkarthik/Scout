package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.InventoryComponentFilterValuesResponse;
import com.prototype.vulnwatch.dto.InventoryComponentPageResponse;
import com.prototype.vulnwatch.service.InventoryService;
import java.util.List;
import com.prototype.vulnwatch.service.TenantService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/inventory")
public class InventoryController {

    private final TenantService tenantService;
    private final InventoryService inventoryService;

    public InventoryController(TenantService tenantService, InventoryService inventoryService) {
        this.tenantService = tenantService;
        this.inventoryService = inventoryService;
    }

    @GetMapping("/components")
    public InventoryComponentPageResponse listComponents(
            @RequestParam(required = false) List<AssetType> assetType,
            @RequestParam(required = false) List<InventoryComponentStatus> componentStatus,
            @RequestParam(required = false) List<String> sourceSystem,
            @RequestParam(required = false) List<String> ecosystem,
            @RequestParam(required = false) List<String> reviewCategory,
            @RequestParam(required = false) String query,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "25") int size
    ) {
        Tenant tenant = tenantService.getDefaultTenant();
        return inventoryService.listComponentsPage(tenant, assetType, componentStatus, sourceSystem, ecosystem, reviewCategory, query, page, size);
    }

    @GetMapping("/components/filters")
    public InventoryComponentFilterValuesResponse componentFilters() {
        Tenant tenant = tenantService.getDefaultTenant();
        return inventoryService.listComponentFilterValues(tenant);
    }
}
