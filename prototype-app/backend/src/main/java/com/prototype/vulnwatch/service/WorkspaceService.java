package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.config.TenantAuthenticationDetails;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class WorkspaceService {

    private final TenantService tenantService;
    private final TenantLifecycleGuardService tenantLifecycleGuardService;
    private final AtomicReference<Tenant> cachedWorkspace = new AtomicReference<>();
    private final boolean requireTenantContext;

    public WorkspaceService(
            TenantService tenantService,
            TenantLifecycleGuardService tenantLifecycleGuardService,
            @Value("${app.tenancy.require-tenant-context:true}") boolean requireTenantContext
    ) {
        this.tenantService = tenantService;
        this.tenantLifecycleGuardService = tenantLifecycleGuardService;
        this.requireTenantContext = requireTenantContext;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void warmCache() {
        if (requireTenantContext) {
            return;
        }
        try {
            refreshWorkspace();
        } catch (ResponseStatusException ignored) {
            cachedWorkspace.set(null);
        }
    }

    public Tenant getWorkspace() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getDetails() instanceof TenantAuthenticationDetails details) {
            if (details.roles().contains("PLATFORM_OWNER") && details.tenantId() == null) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Platform owner must switch into an approved tenant context");
            }
        }
        UUID currentTenantId = TenantContext.getCurrentTenantId();
        if (currentTenantId != null) {
            Tenant tenant = tenantService.resolveTenantUuid(currentTenantId);
            tenantLifecycleGuardService.assertTenantAccessible(tenant);
            return tenant;
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
        if (requireTenantContext) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Tenant context is required");
        }
        Tenant workspace = TenantContext.runAsPlatform(tenantService::getDefaultTenant);
        tenantLifecycleGuardService.assertTenantAccessible(workspace);
        cachedWorkspace.set(workspace);
        return workspace;
    }
}
