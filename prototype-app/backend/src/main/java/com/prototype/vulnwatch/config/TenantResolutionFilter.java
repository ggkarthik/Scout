package com.prototype.vulnwatch.config;

import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.WorkspaceService;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class TenantResolutionFilter implements Filter {

    private final WorkspaceService workspaceService;
    private final TenantService tenantService;
    private final boolean allowHeaderTenantSelection;
    private final boolean requireTenantContext;

    public TenantResolutionFilter(
            WorkspaceService workspaceService,
            TenantService tenantService,
            @Value("${app.tenancy.allow-header-tenant-selection:true}") boolean allowHeaderTenantSelection,
            @Value("${app.tenancy.require-tenant-context:false}") boolean requireTenantContext
    ) {
        this.workspaceService = workspaceService;
        this.tenantService = tenantService;
        this.allowHeaderTenantSelection = allowHeaderTenantSelection;
        this.requireTenantContext = requireTenantContext;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        try {
            resolveAndSetTenant((HttpServletRequest) req);
            chain.doFilter(req, res);
        } finally {
            TenantContext.clear();
        }
    }

    private void resolveAndSetTenant(HttpServletRequest req) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getDetails() instanceof TenantAuthenticationDetails details) {
            TenantContext.setCurrentTenantId(details.tenantId());
            putTenantMdc(details.tenantId());
            return;
        }
        if (allowHeaderTenantSelection) {
            String tenantId = req.getHeader("X-Tenant-ID");
            if (tenantId != null && !tenantId.isBlank()) {
                try {
                    TenantContext.setCurrentTenantId(tenantService.resolveTenantUuid(UUID.fromString(tenantId.trim())).getId());
                    putTenantMdc(TenantContext.getCurrentTenantId());
                    return;
                } catch (IllegalArgumentException ignored) {
                    // Fall through to workspace compatibility.
                }
            }
        }
        if (requireTenantContext) {
            TenantContext.clear();
            putTenantMdc(null);
            return;
        }
        TenantContext.setCurrentTenantId(workspaceService.getWorkspaceId());
        putTenantMdc(TenantContext.getCurrentTenantId());
    }

    private void putTenantMdc(UUID tenantId) {
        if (tenantId == null) {
            MDC.remove(RequestCorrelationFilter.TENANT_ID_MDC_KEY);
            return;
        }
        MDC.put(RequestCorrelationFilter.TENANT_ID_MDC_KEY, tenantId.toString());
    }
}
