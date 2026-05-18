package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.TenantSupportGrantRequest;
import com.prototype.vulnwatch.dto.TenantSupportGrantResponse;
import com.prototype.vulnwatch.security.SensitiveTenantAction;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.TenantAccessControlService;
import com.prototype.vulnwatch.service.TenantSupportGrantService;
import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class TenantSupportGrantController {

    private final TenantSupportGrantService tenantSupportGrantService;
    private final RequestActorService requestActorService;
    private final TenantAccessControlService tenantAccessControlService;
    private final AuditEventService auditEventService;

    public TenantSupportGrantController(
            TenantSupportGrantService tenantSupportGrantService,
            RequestActorService requestActorService,
            TenantAccessControlService tenantAccessControlService,
            AuditEventService auditEventService
    ) {
        this.tenantSupportGrantService = tenantSupportGrantService;
        this.requestActorService = requestActorService;
        this.tenantAccessControlService = tenantAccessControlService;
        this.auditEventService = auditEventService;
    }

    @GetMapping("/tenants/{tenantId}/support-grants")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN')")
    public List<TenantSupportGrantResponse> listForTenant(@PathVariable UUID tenantId) {
        tenantAccessControlService.assertTenantAccess(requestActorService.currentActor(), tenantId);
        return tenantSupportGrantService.listForTenant(tenantId);
    }

    @PostMapping("/tenants/{tenantId}/support-grants")
    @PreAuthorize("hasRole('TENANT_ADMIN')")
    @SensitiveTenantAction("tenant.support_grant.created")
    public TenantSupportGrantResponse create(
            @PathVariable UUID tenantId,
            @Valid @RequestBody TenantSupportGrantRequest request
    ) {
        tenantAccessControlService.assertTenantAccess(requestActorService.currentActor(), tenantId);
        TenantSupportGrantResponse response = tenantSupportGrantService.create(tenantId, requestActorService.currentActor().userId(), request);
        auditEventService.record(
                "tenant.support_grant.created",
                "tenant_support_grant",
                response.id().toString(),
                "{\"tenantId\":\"" + tenantId + "\",\"invitedPlatformSubject\":\"" + response.invitedPlatformSubject() + "\"}");
        return response;
    }

    @DeleteMapping("/tenants/{tenantId}/support-grants/{grantId}")
    @PreAuthorize("hasRole('TENANT_ADMIN')")
    @SensitiveTenantAction("tenant.support_grant.revoked")
    public TenantSupportGrantResponse revoke(@PathVariable UUID tenantId, @PathVariable UUID grantId) {
        tenantAccessControlService.assertTenantAccess(requestActorService.currentActor(), tenantId);
        TenantSupportGrantResponse response = tenantSupportGrantService.revoke(tenantId, grantId, requestActorService.currentActor().userId());
        auditEventService.record(
                "tenant.support_grant.revoked",
                "tenant_support_grant",
                response.id().toString(),
                "{\"tenantId\":\"" + tenantId + "\"}");
        return response;
    }

    @GetMapping("/platform/support-grants")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public List<TenantSupportGrantResponse> listForPlatformOwner() {
        return tenantSupportGrantService.listForPlatformOwner(requestActorService.currentActor().userId());
    }

    @PostMapping("/platform/support-grants/{grantId}/accept")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public TenantSupportGrantResponse accept(@PathVariable UUID grantId) {
        TenantSupportGrantResponse response = tenantSupportGrantService.accept(grantId, requestActorService.currentActor().userId());
        auditEventService.record(
                "platform.support_grant.accepted",
                "tenant_support_grant",
                response.id().toString(),
                "{\"tenantId\":\"" + response.tenantId() + "\"}");
        return response;
    }
}
