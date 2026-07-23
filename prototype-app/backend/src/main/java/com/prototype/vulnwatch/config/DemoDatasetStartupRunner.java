package com.prototype.vulnwatch.config;

import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.service.CustomerDemoDatasetService;
import com.prototype.vulnwatch.service.DemoDatasetProvisioningService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Component
public class DemoDatasetStartupRunner {

    private static final Logger LOG = LoggerFactory.getLogger(DemoDatasetStartupRunner.class);

    private final String tenantSlug;
    private final TenantRepository tenantRepository;
    private final DemoDatasetProvisioningService provisioningService;

    public DemoDatasetStartupRunner(
            @Value("${app.demo-data.seed-tenant-slug:}") String tenantSlug,
            TenantRepository tenantRepository,
            DemoDatasetProvisioningService provisioningService
    ) {
        this.tenantSlug = tenantSlug == null ? "" : tenantSlug.trim();
        this.tenantRepository = tenantRepository;
        this.provisioningService = provisioningService;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void seedConfiguredTenant() {
        if (tenantSlug.isBlank()) {
            return;
        }
        var tenant = tenantRepository.findBySlugIgnoreCase(tenantSlug)
                .orElseThrow(() -> new IllegalStateException("Demo seed tenant slug not found: " + tenantSlug));
        if (CustomerDemoDatasetService.DATASET_VERSION.equals(DemoDatasetProvisioningService.version(tenant))
                && !provisioningService.needsRepair(tenant)) {
            LOG.info("Demo dataset {} is already installed for tenant {}",
                    DemoDatasetProvisioningService.version(tenant), tenantSlug);
            return;
        }
        var summary = provisioningService.requestAndSeed(tenant.getId());
        LOG.info("Installed demo dataset {} for tenant {}: {}", CustomerDemoDatasetService.DATASET_VERSION, tenantSlug, summary);
    }
}
