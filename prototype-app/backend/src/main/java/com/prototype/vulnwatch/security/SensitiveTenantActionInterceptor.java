package com.prototype.vulnwatch.security;

import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.RequestActor;
import com.prototype.vulnwatch.service.RequestActorService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.HandlerInterceptor;

@Component
public class SensitiveTenantActionInterceptor implements HandlerInterceptor {

    private static final Duration MAX_CONFIRM_AGE = Duration.ofMinutes(2);

    private final RequestActorService requestActorService;
    private final ObjectProvider<AuditEventService> auditEventServiceProvider;

    public SensitiveTenantActionInterceptor(
            RequestActorService requestActorService,
            ObjectProvider<AuditEventService> auditEventServiceProvider
    ) {
        this.requestActorService = requestActorService;
        this.auditEventServiceProvider = auditEventServiceProvider;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (!(handler instanceof HandlerMethod handlerMethod) || !requiresConfirmation(handlerMethod)) {
            return true;
        }
        RequestActor actor = requestActorService.currentActor();
        if (!actor.actingAsPlatformOwner()) {
            return true;
        }
        String confirmed = request.getHeader("X-Platform-Action-Confirm");
        String tenantId = request.getHeader("X-Platform-Action-Tenant");
        String confirmedAt = request.getHeader("X-Platform-Action-Time");
        if (!"true".equalsIgnoreCase(confirmed)) {
            throw new ResponseStatusException(HttpStatus.PRECONDITION_REQUIRED, "Platform owner confirmation is required for tenant-scoped sensitive actions");
        }
        if (actor.tenantId() == null || tenantId == null || !actor.tenantId().toString().equals(tenantId.trim())) {
            throw new ResponseStatusException(HttpStatus.PRECONDITION_REQUIRED, "Confirmed tenant context does not match the active tenant");
        }
        Instant confirmationTime = parseConfirmationTime(confirmedAt);
        if (confirmationTime.isBefore(Instant.now().minus(MAX_CONFIRM_AGE))) {
            throw new ResponseStatusException(HttpStatus.PRECONDITION_REQUIRED, "Platform owner confirmation has expired");
        }
        AuditEventService auditEventService = auditEventServiceProvider.getIfAvailable();
        if (auditEventService != null) {
            auditEventService.record(
                    "platform.tenant_action.confirmed",
                    "tenant",
                    actor.tenantId().toString(),
                    "{\"method\":\"" + request.getMethod() + "\",\"path\":\"" + request.getRequestURI() + "\"}");
        }
        return true;
    }

    private boolean requiresConfirmation(HandlerMethod handlerMethod) {
        return handlerMethod.hasMethodAnnotation(SensitiveTenantAction.class)
                || handlerMethod.getBeanType().isAnnotationPresent(SensitiveTenantAction.class);
    }

    private Instant parseConfirmationTime(String confirmedAt) {
        if (confirmedAt == null || confirmedAt.isBlank()) {
            throw new ResponseStatusException(HttpStatus.PRECONDITION_REQUIRED, "Platform owner confirmation timestamp is required");
        }
        try {
            return Instant.parse(confirmedAt.trim());
        } catch (DateTimeParseException ex) {
            throw new ResponseStatusException(HttpStatus.PRECONDITION_REQUIRED, "Platform owner confirmation timestamp is invalid");
        }
    }
}
