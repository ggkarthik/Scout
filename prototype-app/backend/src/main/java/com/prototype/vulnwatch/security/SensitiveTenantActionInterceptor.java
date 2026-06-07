package com.prototype.vulnwatch.security;

import com.prototype.vulnwatch.service.RequestActor;
import com.prototype.vulnwatch.service.RequestActorService;
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

    public SensitiveTenantActionInterceptor(
            RequestActorService requestActorService
    ) {
        this.requestActorService = requestActorService;
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
        throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Platform owners cannot perform tenant-scoped actions");
    }

    private boolean requiresConfirmation(HandlerMethod handlerMethod, String method) {
        if (!isSafeMethod(method)) {
            return true;
        }
        return handlerMethod.hasMethodAnnotation(SensitiveTenantAction.class)
                || handlerMethod.getBeanType().isAnnotationPresent(SensitiveTenantAction.class);
    }

    private boolean isSafeMethod(String method) {
        return "GET".equalsIgnoreCase(method)
                || "HEAD".equalsIgnoreCase(method)
                || "OPTIONS".equalsIgnoreCase(method);
    }
}
