package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class TenantBootstrapService {

    private final TenantRepository tenantRepository;
    private final TenantSchemaService tenantSchemaService;

    public TenantBootstrapService(
            TenantRepository tenantRepository,
            TenantSchemaService tenantSchemaService
    ) {
        this.tenantRepository = tenantRepository;
        this.tenantSchemaService = tenantSchemaService;
    }

    @EventListener(ApplicationReadyEvent.class)
    @Transactional
    public void ensureBootstrapTenant() {
        tenantSchemaService.ensureSchemaExists(tenantSchemaService.defaultSchemaName());

        Tenant defaultTenant = tenantRepository.findByNameIgnoreCase(TenantService.DEFAULT_TENANT_NAME)
                .orElseGet(() -> {
                    Tenant tenant = new Tenant();
                    tenant.setName(TenantService.DEFAULT_TENANT_NAME);
                    tenant.setSlug("default-workspace");
                    tenant.setSchemaName(tenantSchemaService.defaultSchemaName());
                    return tenantRepository.save(tenant);
                });

        boolean changed = false;
        if (defaultTenant.getSchemaName() == null || defaultTenant.getSchemaName().isBlank()) {
            defaultTenant.setSchemaName(tenantSchemaService.defaultSchemaName());
            changed = true;
        }

        for (Tenant tenant : tenantRepository.findAll()) {
            if (tenant.getSchemaName() == null || tenant.getSchemaName().isBlank()) {
                tenant.setSchemaName(tenantSchemaService.deriveSchemaName(tenant.getSlug()));
                tenant.setUpdatedAt(Instant.now());
                tenantRepository.save(tenant);
            }
            tenantSchemaService.ensureSchemaExists(tenant.getSchemaName());
        }

        if (changed) {
            defaultTenant.setUpdatedAt(Instant.now());
            tenantRepository.save(defaultTenant);
        }
    }
}
