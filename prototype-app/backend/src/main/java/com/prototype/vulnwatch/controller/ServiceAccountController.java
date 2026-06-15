package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.ServiceAccount;
import com.prototype.vulnwatch.dto.ServiceAccountRequest;
import com.prototype.vulnwatch.dto.ServiceAccountResponse;
import com.prototype.vulnwatch.security.SensitiveTenantAction;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.IdentityAdministrationService;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.TenantAccessControlService;
import java.util.List;
import java.util.UUID;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.security.access.prepost.PreAuthorize;
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
    private final TenantAccessControlService tenantAccessControlService;

    public ServiceAccountController(
            IdentityAdministrationService identityAdministrationService,
            RequestActorService requestActorService,
            AuditEventService auditEventService,
            TenantAccessControlService tenantAccessControlService
    ) {
        this.identityAdministrationService = identityAdministrationService;
        this.requestActorService = requestActorService;
        this.auditEventService = auditEventService;
        this.tenantAccessControlService = tenantAccessControlService;
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN')")
    public List<ServiceAccountResponse> list() {
        UUID tenantId = requestActorService.currentActor().tenantId();
        tenantAccessControlService.assertTenantAccess(requestActorService.currentActor(), tenantId);
        return identityAdministrationService.listServiceAccounts(tenantId).stream()
                .map(this::toResponse)
                .toList();
    }

    @PostMapping
    @PreAuthorize("hasRole('TENANT_ADMIN')")
    @SensitiveTenantAction("service_account.created")
    public ServiceAccountResponse create(@RequestBody ServiceAccountRequest request) {
        var actor = requestActorService.currentActor();
        UUID tenantId = request.tenantId() == null ? actor.tenantId() : request.tenantId();
        tenantAccessControlService.assertTenantAccess(actor, tenantId);
        ServiceAccount account = identityAdministrationService.createServiceAccount(
                tenantId,
                request.name(),
                request.keyId(),
                request.role());
        auditEventService.record("service_account.created", "service_account", account.getId().toString(),
                "{\"tenantId\":\"" + tenantId + "\",\"role\":\"" + account.getRole() + "\"}");
        return toResponse(account);
    }

    @DeleteMapping("/{accountId}")
    @PreAuthorize("hasRole('TENANT_ADMIN')")
    @SensitiveTenantAction("service_account.deleted")
    public void delete(@PathVariable UUID accountId) {
        var actor = requestActorService.currentActor();
        tenantAccessControlService.assertTenantAccess(actor, actor.tenantId());
        identityAdministrationService.deleteServiceAccount(actor.tenantId(), accountId);
        auditEventService.record("service_account.deleted", "service_account", accountId.toString(),
                "{\"tenantId\":\"" + actor.tenantId() + "\"}");
    }

    @PostMapping("/{accountId}/deactivate")
    @PreAuthorize("hasRole('TENANT_ADMIN')")
    @SensitiveTenantAction("service_account.deactivated")
    public ServiceAccountResponse deactivate(@PathVariable UUID accountId) {
        var actor = requestActorService.currentActor();
        tenantAccessControlService.assertTenantAccess(actor, actor.tenantId());
        ServiceAccount account = identityAdministrationService.deactivateServiceAccount(actor.tenantId(), accountId);
        auditEventService.record("service_account.deactivated", "service_account", accountId.toString(),
                "{\"tenantId\":\"" + actor.tenantId() + "\",\"status\":\"" + account.getStatus() + "\"}");
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
