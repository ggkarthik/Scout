package com.prototype.vulnwatch.config;

import com.prototype.vulnwatch.service.TenantSchemaStatusService;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

/** Prevents production runtime from serving before the owner-run platform/tenant bootstrap is complete. */
@Service
@Profile({"prod", "preprod"})
public class TenantBootstrapPrerequisiteService {
    private final TenantSchemaStatusService schemas;

    public TenantBootstrapPrerequisiteService(TenantSchemaStatusService schemas) {
        this.schemas = schemas;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void requireCurrentTenantSchemas() {
        long failures = schemas.readinessFailures(TenantSchemaStatusService.TARGET_VERSION);
        if (failures > 0) {
            throw new IllegalStateException("Production bootstrap prerequisite is incomplete for " + failures
                    + " tenant schema(s); run ProductionBootstrapCli before starting runtime");
        }
    }
}
