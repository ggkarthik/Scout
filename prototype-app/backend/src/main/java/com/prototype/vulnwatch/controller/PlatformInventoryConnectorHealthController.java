package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.InventoryConnectorHealthResponse;
import com.prototype.vulnwatch.service.PlatformInventoryConnectorHealthService;
import java.util.List;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/platform/inventory-connectors")
public class PlatformInventoryConnectorHealthController {

    private final PlatformInventoryConnectorHealthService platformInventoryConnectorHealthService;

    public PlatformInventoryConnectorHealthController(
            PlatformInventoryConnectorHealthService platformInventoryConnectorHealthService
    ) {
        this.platformInventoryConnectorHealthService = platformInventoryConnectorHealthService;
    }

    @GetMapping("/health")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public List<InventoryConnectorHealthResponse> listHealth() {
        return platformInventoryConnectorHealthService.listInventoryConnectorHealth();
    }
}
