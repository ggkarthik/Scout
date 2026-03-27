package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;

@Service
public class WorkspaceService {

    private final TenantService tenantService;
    private final AtomicReference<Tenant> cachedWorkspace = new AtomicReference<>();

    public WorkspaceService(TenantService tenantService) {
        this.tenantService = tenantService;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void warmCache() {
        refreshWorkspace();
    }

    public Tenant getWorkspace() {
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
