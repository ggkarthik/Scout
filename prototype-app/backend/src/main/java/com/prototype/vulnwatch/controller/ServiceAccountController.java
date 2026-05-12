package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.ServiceAccount;
import com.prototype.vulnwatch.dto.ServiceAccountRequest;
import com.prototype.vulnwatch.dto.ServiceAccountResponse;
import com.prototype.vulnwatch.security.SensitiveTenantAction;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.IdentityAdministrationService;
import com.prototype.vulnwatch.service.RequestActorService;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/service-accounts")
public class ServiceAccountController {

    private final IdentityAdministrationService identityAdministrationService;
    private final RequestActorService requestActorService;
    private final AuditEventService auditEventService;

    public ServiceAccountController(
            IdentityAdministrationService identityAdministrationService,
            RequestActorService requestActorService,
            AuditEventService auditEventService
    ) {
        this.identityAdministrationService = identityAdministrationService;
        this.requestActorService = requestActorService;
        this.auditEventService = auditEventService;
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN')")
    public List<ServiceAccountResponse> list() {
        UUID tenantId = requestActorService.currentActor().tenantId();
        return identityAdministrationService.listServiceAccounts(tenantId).stream()
                .map(this::toResponse)
                .toList();
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN')")
    @SensitiveTenantAction("service_account.created")
    public ServiceAccountResponse create(@RequestBody ServiceAccountRequest request) {
        var actor = requestActorService.currentActor();
        UUID tenantId = request.tenantId() == null ? actor.tenantId() : request.tenantId();
        if (!actor.hasRole("PLATFORM_OWNER") && (actor.tenantId() == null || !actor.tenantId().equals(tenantId))) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Cannot manage service accounts for another tenant");
        }
        ServiceAccount account = identityAdministrationService.createServiceAccount(
                tenantId,
                request.name(),
                request.keyId(),
                request.role());
        auditEventService.record("service_account.created", "service_account", account.getId().toString(),
                "{\"tenantId\":\"" + tenantId + "\",\"role\":\"" + account.getRole() + "\"}");
        return toResponse(account);
    }

    private ServiceAccountResponse toResponse(ServiceAccount account) {
        return new ServiceAccountResponse(
                account.getId(),
                account.getTenant() == null ? null : account.getTenant().getId(),
                account.getName(),
                account.getKeyId(),
                account.getRole(),
                account.getStatus(),
                account.getCreatedAt(),
                account.getLastUsedAt());
    }
}
