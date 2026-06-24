package com.prototype.vulnwatch.security;

import com.prototype.vulnwatch.service.RequestActor;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.TenantSupportGrantService;
import com.prototype.vulnwatch.web.PlatformAdminRequestPaths;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.HandlerInterceptor;

@Component
public class SensitiveTenantActionInterceptor implements HandlerInterceptor {

    private final RequestActorService requestActorService;
    private final TenantSupportGrantService tenantSupportGrantService;

    public SensitiveTenantActionInterceptor(
            RequestActorService requestActorService,
            TenantSupportGrantService tenantSupportGrantService
    ) {
        this.requestActorService = requestActorService;
        this.tenantSupportGrantService = tenantSupportGrantService;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (!(handler instanceof HandlerMethod handlerMethod) || !requiresConfirmation(handlerMethod, request.getMethod())) {
            return true;
        }
        RequestActor actor = requestActorService.currentActor();
        if (!actor.actingAsPlatformOwner()) {
            return true;
        }
        // Platform and operations endpoints are platform-administration actions gated by ROLE_PLATFORM_OWNER;
        // they are not tenant-data operations so the support-grant check does not apply.
        if (PlatformAdminRequestPaths.isPlatformAdminPath(request.getRequestURI())) {
            return true;
        }
        if (actor.tenantId() == null) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Platform owner tenant context is required");
        }
        tenantSupportGrantService.requireActiveGrantForWrite(actor.userId(), actor.tenantId());
        return true;
    }

    private boolean requiresConfirmation(HandlerMethod handlerMethod, String method) {
        return handlerMethod.hasMethodAnnotation(SensitiveTenantAction.class)
                || handlerMethod.getBeanType().isAnnotationPresent(SensitiveTenantAction.class);
    }
}
