package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Supplier;
import org.springframework.stereotype.Service;

@Service
public class TenantSchemaExecutionService {

    private final TenantService tenantService;

    public TenantSchemaExecutionService(TenantService tenantService) {
        this.tenantService = tenantService;
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
        String schemaName = tenant.getSchemaName();
        if (schemaName == null || schemaName.isBlank()) {
            Tenant resolved = tenantService.resolveTenantUuid(tenant.getId());
            schemaName = resolved.getSchemaName();
        }
        return run(tenant.getId(), schemaName, supplier);
    }

    public <T> T run(UUID tenantId, Supplier<T> supplier) {
        Objects.requireNonNull(supplier, "supplier");
        if (tenantId == null) {
            return supplier.get();
        }
        Tenant tenant = tenantService.resolveTenantUuid(tenantId);
        return run(tenantId, tenant.getSchemaName(), supplier);
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
