package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.annotation.Order;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class TenantBootstrapService {

    private static final Logger log = LoggerFactory.getLogger(TenantBootstrapService.class);

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
    @Order(0)
    public void ensureBootstrapTenant() {
        TenantContext.runAsPlatform(() -> {
            Tenant defaultTenant = tenantRepository.findByNameIgnoreCase(TenantService.DEFAULT_TENANT_NAME)
                    .orElseGet(() -> {
                        Tenant tenant = new Tenant();
                        tenant.setName(TenantService.DEFAULT_TENANT_NAME);
                        tenant.setSlug("default-workspace");
                        tenant.setSchemaName(tenantSchemaService.defaultSchemaName());
                        return tenantRepository.save(tenant);
                    });

            boolean changed = false;
            String normalizedDefaultSchema = tenantSchemaService.defaultSchemaName();
            if (!normalizedDefaultSchema.equals(defaultTenant.getSchemaName())) {
                defaultTenant.setSchemaName(normalizedDefaultSchema);
                defaultTenant.setUpdatedAt(Instant.now());
                changed = true;
            }
            if (changed) {
                tenantRepository.save(defaultTenant);
            }
            warnIfNotReady(defaultTenant, normalizedDefaultSchema);

            for (Tenant tenant : tenantRepository.findAll()) {
                String normalizedSchema = tenant.getSchemaName() == null || tenant.getSchemaName().isBlank()
                        ? tenantSchemaService.deriveSchemaName(tenant.getSlug())
                        : tenantSchemaService.normalizeSchemaName(tenant.getSchemaName());
                if (!normalizedSchema.equals(tenant.getSchemaName())) {
                    tenant.setSchemaName(normalizedSchema);
                    tenant.setUpdatedAt(Instant.now());
                    tenantRepository.save(tenant);
                }
                if ("ACTIVE".equalsIgnoreCase(tenant.getStatus())) {
                    warnIfNotReady(tenant, tenant.getSchemaName());
                }
            }
        });
    }

    private void warnIfNotReady(Tenant tenant, String schemaName) {
        try {
            tenantSchemaService.assertSchemaReady(schemaName);
        } catch (RuntimeException ex) {
            log.warn("Tenant schema is not ready; runtime remains alive and tenant access stays blocked"
                            + " tenantId={} schema={} reason={}",
                    tenant.getId(), schemaName, ex.getMessage());
        }
    }
}
