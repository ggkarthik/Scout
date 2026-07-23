package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.service.CustomerDemoDatasetService;
import com.prototype.vulnwatch.service.DemoDatasetProvisioningService;
import java.util.UUID;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/platform/tenants")
public class DemoDatasetController {

    private final DemoDatasetProvisioningService provisioningService;

    public DemoDatasetController(DemoDatasetProvisioningService provisioningService) {
        this.provisioningService = provisioningService;
    }

    @PostMapping("/{tenantId}/demo-data")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public CustomerDemoDatasetService.DemoDatasetSummary seed(@PathVariable UUID tenantId) {
        return provisioningService.requestAndSeed(tenantId);
    }
}
