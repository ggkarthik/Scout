package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class WorkspaceService {

    private final TenantService tenantService;
    private final AtomicReference<Tenant> cachedWorkspace = new AtomicReference<>();
    private final boolean requireTenantContext;

    public WorkspaceService(
            TenantService tenantService,
            @Value("${app.tenancy.require-tenant-context:false}") boolean requireTenantContext
    ) {
        this.tenantService = tenantService;
        this.requireTenantContext = requireTenantContext;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void warmCache() {
        refreshWorkspace();
    }

    public Tenant getWorkspace() {
        UUID currentTenantId = TenantContext.getCurrentTenantId();
        if (currentTenantId != null) {
            return tenantService.resolveTenantUuid(currentTenantId);
        }
        if (requireTenantContext) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Tenant context is required");
        }
        Tenant cached = cachedWorkspace.get();
        if (cached != null) {
            return cached;
        }
        return refreshWorkspace();
    }

    public UUID getWorkspaceId() {
        Tenant workspace = getWorkspace();
        return workspace == null ? null : workspace.getId();
    }

    public Tenant refreshWorkspace() {
        Tenant workspace = tenantService.getDefaultTenant();
        cachedWorkspace.set(workspace);
        return workspace;
    }
}
