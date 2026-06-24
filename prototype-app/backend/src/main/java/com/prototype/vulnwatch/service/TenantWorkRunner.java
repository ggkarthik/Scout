package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class TenantWorkRunner {

    private static final Logger LOG = LoggerFactory.getLogger(TenantWorkRunner.class);

    private final TenantService tenantService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final TransactionTemplate transactionTemplate;

    public TenantWorkRunner(
            TenantService tenantService,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            PlatformTransactionManager transactionManager
    ) {
        this.tenantService = tenantService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
    }

    public void forEachActiveTenant(Consumer<Tenant> work) {
        try {
            for (Tenant tenant : tenantService.listActiveTenants()) {
                try {
                    runScoped(tenant, () -> {
                        work.accept(tenant);
                        return null;
                    });
                } catch (Exception ex) {
                    LOG.warn("Tenant-scoped background work failed for tenant {}: {}", tenant.getId(), ex.getMessage(), ex);
                }
            }
        } catch (Exception ex) {
            LOG.warn("Tenant-scoped background work failed before tenant iteration: {}", ex.getMessage(), ex);
        }
    }

    public void runScoped(Tenant tenant, Runnable work) {
        runScoped(tenant, () -> {
            work.run();
            return null;
        });
    }

    public <T> T runScoped(Tenant tenant, Supplier<T> work) {
        return tenantSchemaExecutionService.run(tenant, () -> transactionTemplate.execute(status -> work.get()));
    }

    public void runScoped(UUID tenantId, Runnable work) {
        runScoped(tenantId, () -> {
            work.run();
            return null;
        });
    }

    public <T> T runScoped(UUID tenantId, Supplier<T> work) {
        return tenantSchemaExecutionService.run(tenantId, () -> transactionTemplate.execute(status -> work.get()));
    }
}
