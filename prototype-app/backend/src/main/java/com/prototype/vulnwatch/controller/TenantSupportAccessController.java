package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.TenantMembership;
import com.prototype.vulnwatch.dto.PlatformOwnerTenantMembershipRequest;
import com.prototype.vulnwatch.dto.TenantMemberResponse;
import com.prototype.vulnwatch.dto.TenantSupportGrantRequest;
import com.prototype.vulnwatch.dto.TenantSupportGrantResponse;
import com.prototype.vulnwatch.security.SensitiveTenantAction;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.IdentityAdministrationService;
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
public class TenantSupportAccessController {
    private final TenantSupportGrantService grantService;
    private final IdentityAdministrationService identityService;
    private final TenantAccessControlService accessControlService;
    private final RequestActorService actorService;
    private final AuditEventService auditEventService;

    public TenantSupportAccessController(
            TenantSupportGrantService grantService,
            IdentityAdministrationService identityService,
            TenantAccessControlService accessControlService,
            RequestActorService actorService,
            AuditEventService auditEventService
    ) {
        this.grantService = grantService;
        this.identityService = identityService;
        this.accessControlService = accessControlService;
        this.actorService = actorService;
        this.auditEventService = auditEventService;
    }

    @GetMapping("/tenants/{tenantId}/support-grants")
    @PreAuthorize("hasRole('TENANT_ADMIN')")
    public List<TenantSupportGrantResponse> listTenantGrants(@PathVariable UUID tenantId) {
        accessControlService.assertTenantAccess(actorService.currentActor(), tenantId);
        return grantService.listForTenant(tenantId);
    }

    @PostMapping("/tenants/{tenantId}/support-grants")
    @PreAuthorize("hasRole('TENANT_ADMIN')")
    @SensitiveTenantAction("support.grant.created")
    public TenantSupportGrantResponse createGrant(
            @PathVariable UUID tenantId,
            @Valid @RequestBody TenantSupportGrantRequest request
    ) {
        accessControlService.assertTenantAccess(actorService.currentActor(), tenantId);
        var response = grantService.create(tenantId, actorService.currentActor().userId(), request);
        auditEventService.record("support.grant.created", "tenant_support_grant", response.id().toString(),
                "{\"tenantId\":\"" + tenantId + "\",\"accessMode\":\"" + response.accessMode() + "\"}");
        return response;
    }

    @DeleteMapping("/tenants/{tenantId}/support-grants/{grantId}")
    @PreAuthorize("hasRole('TENANT_ADMIN')")
    @SensitiveTenantAction("support.grant.revoked")
    public TenantSupportGrantResponse revokeGrant(@PathVariable UUID tenantId, @PathVariable UUID grantId) {
        accessControlService.assertTenantAccess(actorService.currentActor(), tenantId);
        var response = grantService.revoke(tenantId, grantId, actorService.currentActor().userId());
        auditEventService.record("support.grant.revoked", "tenant_support_grant", grantId.toString(),
                "{\"tenantId\":\"" + tenantId + "\"}");
        return response;
    }

    @GetMapping("/auth/support-grants")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public List<TenantSupportGrantResponse> listInvitedGrants() {
        return grantService.listForPlatformOwner(actorService.currentActor().userId());
    }

    @PostMapping("/auth/support-grants/{grantId}/accept")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public TenantSupportGrantResponse acceptGrant(@PathVariable UUID grantId) {
        var response = grantService.accept(grantId, actorService.currentActor().userId());
        auditEventService.recordExplicitActor(
                response.tenantId(), actorService.currentActor().userId(), "PLATFORM_OWNER",
                "support.grant.accepted", "tenant_support_grant", grantId.toString(), null, "SUCCESS");
        return response;
    }

    @PostMapping("/tenants/{tenantId}/platform-memberships")
    @PreAuthorize("hasRole('TENANT_ADMIN')")
    @SensitiveTenantAction("platform_owner.membership.granted")
    public TenantMemberResponse grantPlatformOwnerMembership(
            @PathVariable UUID tenantId,
            @Valid @RequestBody PlatformOwnerTenantMembershipRequest request
    ) {
        var actor = actorService.currentActor();
        accessControlService.assertTenantAccess(actor, tenantId);
        TenantMembership membership = identityService.grantPlatformOwnerMembership(
                tenantId, request.subject(), request.role(), actor.userId());
        auditEventService.record("platform_owner.membership.granted", "tenant_membership", membership.getId().toString(),
                "{\"tenantId\":\"" + tenantId + "\",\"role\":\"" + membership.getRole() + "\"}");
        return new TenantMemberResponse(
                membership.getId(), membership.getUser().getId(), membership.getUser().getExternalSubject(),
                membership.getUser().getEmail(), membership.getUser().getDisplayName(), membership.getRole(),
                membership.getStatus(), membership.getCreatedAt());
    }
}
