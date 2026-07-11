package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.dto.AllowedTenantResponse;
import java.util.Comparator;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AllowedTenantContextService {

    private final TenantMembershipRepository tenantMembershipRepository;
    private final TenantLifecycleGuardService tenantLifecycleGuardService;
    private final TenantSupportGrantService tenantSupportGrantService;

    public AllowedTenantContextService(
            TenantMembershipRepository tenantMembershipRepository,
            TenantLifecycleGuardService tenantLifecycleGuardService,
            TenantSupportGrantService tenantSupportGrantService
    ) {
        this.tenantMembershipRepository = tenantMembershipRepository;
        this.tenantLifecycleGuardService = tenantLifecycleGuardService;
        this.tenantSupportGrantService = tenantSupportGrantService;
    }

    @Transactional(readOnly = true)
    public List<AllowedTenantResponse> listAllowedTenants(RequestActor actor) {
        if (actor == null) {
            return List.of();
        }
        if (actor.hasRole("PLATFORM_OWNER")) {
            return tenantSupportGrantService.listActiveGrantsForPlatformOwner(actor.userId()).stream()
                    .sorted(Comparator.comparing(grant -> grant.getTenant().getName(), String.CASE_INSENSITIVE_ORDER))
                    .map(grant -> new AllowedTenantResponse(
                            grant.getTenant().getId().toString(),
                            grant.getTenant().getName(),
                            grant.getTenant().getSlug(),
                            "PLATFORM_OWNER",
                            grant.getAccessMode(),
                            grant.getExpiresAt()))
                    .toList();
        }
        List<AllowedTenantResponse> allowedTenants = tenantMembershipRepository
                .findByUserExternalSubjectAndStatusOrderByCreatedAtAsc(actor.userId(), "ACTIVE").stream()
                .filter(membership -> tenantLifecycleGuardService.isTenantAccessible(membership.getTenant()))
                .map(membership -> new AllowedTenantResponse(
                        membership.getTenant().getId().toString(),
                        membership.getTenant().getName(),
                        membership.getTenant().getSlug(),
                        membership.getRole(),
                        null,
                        null))
                .toList();
        if (allowedTenants.size() > 1) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Multiple active tenant memberships found. Contact support.");
        }
        return allowedTenants;
    }
}
