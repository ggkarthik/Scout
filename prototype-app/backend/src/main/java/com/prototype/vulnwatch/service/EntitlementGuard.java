package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Service
public class EntitlementGuard {

    private final TenantEntitlementService tenantEntitlementService;
    private final AuditEventService auditEventService;

    public EntitlementGuard(TenantEntitlementService tenantEntitlementService, AuditEventService auditEventService) {
        this.tenantEntitlementService = tenantEntitlementService;
        this.auditEventService = auditEventService;
    }

    public void assertEnabled(Tenant tenant, String entitlementKey, String message) {
        TenantEntitlementService.ResolvedEntitlement resolved = tenantEntitlementService.resolve(tenant, entitlementKey);
        if (resolved.enabled()) {
            return;
        }
        auditEventService.record(
                "tenant.entitlement.denied",
                "tenant",
                tenant == null || tenant.getId() == null ? null : tenant.getId().toString(),
                buildDetailsJson(resolved),
                "DENIED");
        throw new EntitlementDeniedException(entitlementKey, resolved.planCode(), message);
    }

    private String buildDetailsJson(TenantEntitlementService.ResolvedEntitlement resolved) {
        String requestPath = currentRequestPath();
        return "{"
                + "\"entitlementKey\":\"" + escapeJson(resolved.key()) + "\","
                + "\"planCode\":\"" + escapeJson(resolved.planCode()) + "\","
                + "\"source\":\"" + escapeJson(resolved.source()) + "\","
                + "\"requestPath\":\"" + escapeJson(requestPath) + "\""
                + "}";
    }

    private String currentRequestPath() {
        try {
            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attributes == null) {
                return "";
            }
            HttpServletRequest request = attributes.getRequest();
            return request == null ? "" : request.getRequestURI();
        } catch (Exception ignored) {
            return "";
        }
    }

    private String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
