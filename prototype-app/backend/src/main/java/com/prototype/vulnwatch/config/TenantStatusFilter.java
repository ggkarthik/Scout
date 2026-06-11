package com.prototype.vulnwatch.config;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.service.TenantContext;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class TenantStatusFilter extends OncePerRequestFilter {

    private static final int HTTP_LOCKED = 423;

    private final TenantRepository tenantRepository;

    public TenantStatusFilter(TenantRepository tenantRepository) {
        this.tenantRepository = tenantRepository;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return !path.startsWith("/api/")
                || path.startsWith("/api/platform/")
                || path.startsWith("/api/auth/")
                || path.startsWith("/api/me");
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        UUID tenantId = TenantContext.getCurrentTenantId();
        if (tenantId != null) {
            Tenant tenant = tenantRepository.findById(tenantId).orElse(null);
            if (tenant == null) {
                response.setStatus(HttpServletResponse.SC_GONE);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.getWriter().write("{\"code\":\"TENANT_DELETED\",\"error\":\"Tenant no longer exists\"}");
                return;
            }
            if (isBlocked(tenant)) {
                response.setStatus(HTTP_LOCKED);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.getWriter().write("{\"code\":\"TENANT_SUSPENDED\",\"error\":\"Tenant is not active\"}");
                return;
            }
        }
        filterChain.doFilter(request, response);
    }

    private boolean isBlocked(Tenant tenant) {
        return tenant.getDeletedAt() != null || !"ACTIVE".equalsIgnoreCase(tenant.getStatus());
    }
}
