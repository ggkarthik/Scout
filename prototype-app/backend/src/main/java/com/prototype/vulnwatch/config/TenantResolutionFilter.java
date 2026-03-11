package com.prototype.vulnwatch.config;

import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantService;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * BLG-007: Populates TenantContext from the X-Tenant-ID request header (or falls
 * back to the default workspace) so that TenantAwareDataSource can set the
 * app.current_tenant_id PostgreSQL session variable on each acquired connection.
 *
 * Not a @Component — registered explicitly via FilterRegistrationBean in
 * TenantIsolationConfig so that @WebMvcTest slice tests do not pick it up
 * (it depends on TenantService/JPA which are not available in slice contexts).
 */
public class TenantResolutionFilter implements Filter {

    private static final Logger LOG = LoggerFactory.getLogger(TenantResolutionFilter.class);
    private static final String TENANT_HEADER = "X-Tenant-ID";

    private final TenantService tenantService;

    public TenantResolutionFilter(TenantService tenantService) {
        this.tenantService = tenantService;
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
        try {
            String header = req.getHeader(TENANT_HEADER);
            java.util.UUID tenantId;
            if (header != null && !header.isBlank()) {
                try {
                    tenantId = java.util.UUID.fromString(header.trim());
                } catch (IllegalArgumentException e) {
                    // Header present but not a UUID — use legacy long ID via TenantService
                    tenantId = tenantService.resolveTenant(null).getId();
                }
            } else {
                tenantId = tenantService.getDefaultTenant().getId();
            }
            TenantContext.setCurrentTenantId(tenantId);
        } catch (Exception ex) {
            // Never block a request due to tenant resolution failure; let it proceed
            // without RLS context (background policy allows unrestricted access).
            LOG.warn("Tenant resolution failed for request {}: {}", req.getRequestURI(), ex.getMessage());
        }
    }
}
