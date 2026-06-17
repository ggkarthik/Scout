package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Supplier;
import org.springframework.stereotype.Service;

@Service
public class TenantSchemaExecutionService {

    private final TenantService tenantService;
    private final TenantSchemaService tenantSchemaService;

    public TenantSchemaExecutionService(TenantService tenantService, TenantSchemaService tenantSchemaService) {
        this.tenantService = tenantService;
        this.tenantSchemaService = tenantSchemaService;
    }

    public void run(Tenant tenant, Runnable runnable) {
        run(tenant, () -> {
            runnable.run();
            return null;
        });
    }

    public <T> T run(Tenant tenant, Supplier<T> supplier) {
        Objects.requireNonNull(supplier, "supplier");
        if (tenant == null || tenant.getId() == null) {
            return supplier.get();
        }
        Tenant resolved = tenant;
        if (tenant.getSchemaName() == null || tenant.getSchemaName().isBlank()) {
            resolved = tenantService.resolveTenantUuid(tenant.getId());
        }
        String schemaName = tenantSchemaService.schemaNameForTenant(resolved);
        tenantSchemaService.ensureSchemaExists(schemaName);
        return run(tenant.getId(), schemaName, supplier);
    }

    public <T> T run(UUID tenantId, Supplier<T> supplier) {
        Objects.requireNonNull(supplier, "supplier");
        if (tenantId == null) {
            return supplier.get();
        }
        Tenant tenant = tenantService.resolveTenantUuid(tenantId);
        String schemaName = tenantSchemaService.schemaNameForTenant(tenant);
        tenantSchemaService.ensureSchemaExists(schemaName);
        return run(tenantId, schemaName, supplier);
    }

    private <T> T run(UUID tenantId, String schemaName, Supplier<T> supplier) {
        UUID previousTenantId = TenantContext.getCurrentTenantId();
        String previousSchema = TenantContext.getCurrentSchemaName();
        try {
            TenantContext.setCurrentTenantId(tenantId);
            TenantContext.setCurrentSchemaName(schemaName);
            return supplier.get();
        } finally {
            if (previousTenantId == null) {
                TenantContext.clear();
            } else {
                TenantContext.setCurrentTenantId(previousTenantId);
                TenantContext.setCurrentSchemaName(previousSchema);
            }
        }
    }
}
