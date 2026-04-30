package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantMembership;
import com.prototype.vulnwatch.dto.TenantCreateRequest;
import com.prototype.vulnwatch.dto.TenantMemberRequest;
import com.prototype.vulnwatch.dto.TenantMemberResponse;
import com.prototype.vulnwatch.dto.TenantResponse;
import com.prototype.vulnwatch.dto.TenantStatusRequest;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.IdentityAdministrationService;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.TenantAdministrationService;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class TenantAdministrationController {

    private final TenantAdministrationService tenantAdministrationService;
    private final IdentityAdministrationService identityAdministrationService;
    private final AuditEventService auditEventService;
    private final RequestActorService requestActorService;

    public TenantAdministrationController(
            TenantAdministrationService tenantAdministrationService,
            IdentityAdministrationService identityAdministrationService,
            AuditEventService auditEventService,
            RequestActorService requestActorService
    ) {
        this.tenantAdministrationService = tenantAdministrationService;
        this.identityAdministrationService = identityAdministrationService;
        this.auditEventService = auditEventService;
        this.requestActorService = requestActorService;
    }

    @GetMapping("/tenants")
    public List<TenantResponse> listTenants() {
        var actor = requestActorService.currentActor();
        if (!actor.hasRole("PLATFORM_OWNER") && actor.tenantId() == null) {
            return List.of();
        }
        if (!actor.hasRole("PLATFORM_OWNER")) {
            return tenantAdministrationService.listTenants().stream()
                    .filter(tenant -> actor.tenantId().equals(tenant.getId()))
                    .map(this::toTenantResponse)
                    .toList();
        }
        return tenantAdministrationService.listTenants().stream().map(this::toTenantResponse).toList();
    }

    @PostMapping("/platform/tenants")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public TenantResponse createTenant(@RequestBody TenantCreateRequest request) {
        Tenant tenant = tenantAdministrationService.createTenant(request.name(), request.slug(), request.planCode(), request.billingRef());
        auditEventService.record("tenant.created", "tenant", tenant.getId().toString(), null);
        return toTenantResponse(tenant);
    }

    @PatchMapping("/platform/tenants/{tenantId}/status")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public TenantResponse updateTenantStatus(@PathVariable UUID tenantId, @RequestBody TenantStatusRequest request) {
        Tenant tenant = tenantAdministrationService.updateStatus(tenantId, request.status());
        auditEventService.record("tenant.status.updated", "tenant", tenant.getId().toString(),
                "{\"status\":\"" + tenant.getStatus() + "\"}");
        return toTenantResponse(tenant);
    }

    @GetMapping("/tenants/{tenantId}/members")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN')")
    public List<TenantMemberResponse> listMembers(@PathVariable UUID tenantId) {
        assertSameTenantOrPlatformOwner(tenantId);
        return identityAdministrationService.listMembers(tenantId).stream()
                .map(this::toMemberResponse)
                .toList();
    }

    @PostMapping("/tenants/{tenantId}/members")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN')")
    public TenantMemberResponse addMember(@PathVariable UUID tenantId, @RequestBody TenantMemberRequest request) {
        assertSameTenantOrPlatformOwner(tenantId);
        TenantMembership membership = identityAdministrationService.addMember(
                tenantId,
                request.subject(),
                request.email(),
                request.displayName(),
                request.role());
        auditEventService.record("tenant.member.added", "tenant_membership", membership.getId().toString(),
                "{\"tenantId\":\"" + tenantId + "\",\"role\":\"" + membership.getRole() + "\"}");
        return toMemberResponse(membership);
    }

    private void assertSameTenantOrPlatformOwner(UUID tenantId) {
        var actor = requestActorService.currentActor();
        if (!actor.hasRole("PLATFORM_OWNER") && (actor.tenantId() == null || !actor.tenantId().equals(tenantId))) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Cannot manage another tenant");
        }
    }

    private TenantResponse toTenantResponse(Tenant tenant) {
        return new TenantResponse(
                tenant.getId(),
                tenant.getName(),
                tenant.getSlug(),
                tenant.getStatus(),
                tenant.getPlanCode(),
                tenant.getBillingRef(),
                tenant.getMaxConnectorCount(),
                tenant.getMaxServiceAccountCount(),
                tenant.getMaxDailySbomUploads(),
                tenant.getMaxExportRows(),
                tenant.getMaxDailyExposureRefreshes(),
                tenant.getCreatedAt(),
                tenant.getUpdatedAt());
    }

    private TenantMemberResponse toMemberResponse(TenantMembership membership) {
        return new TenantMemberResponse(
                membership.getId(),
                membership.getUser().getId(),
                membership.getUser().getExternalSubject(),
                membership.getUser().getEmail(),
                membership.getUser().getDisplayName(),
                membership.getRole(),
                membership.getStatus(),
                membership.getCreatedAt());
    }
}
