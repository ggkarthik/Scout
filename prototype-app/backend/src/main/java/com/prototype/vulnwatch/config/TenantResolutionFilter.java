package com.prototype.vulnwatch.config;

import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.WorkspaceService;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
public class TenantResolutionFilter implements Filter {

    private final WorkspaceService workspaceService;

    public TenantResolutionFilter(WorkspaceService workspaceService) {
        this.workspaceService = workspaceService;
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
        TenantContext.setCurrentTenantId(workspaceService.getWorkspaceId());
    }
}
