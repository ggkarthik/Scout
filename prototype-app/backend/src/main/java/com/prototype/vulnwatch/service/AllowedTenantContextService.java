package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.dto.AllowedTenantResponse;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AllowedTenantContextService {

    private final TenantMembershipRepository tenantMembershipRepository;
    private final TenantSupportGrantService tenantSupportGrantService;
    private final TenantLifecycleGuardService tenantLifecycleGuardService;

    public AllowedTenantContextService(
            TenantMembershipRepository tenantMembershipRepository,
            TenantSupportGrantService tenantSupportGrantService,
            TenantLifecycleGuardService tenantLifecycleGuardService
    ) {
        this.tenantMembershipRepository = tenantMembershipRepository;
        this.tenantSupportGrantService = tenantSupportGrantService;
        this.tenantLifecycleGuardService = tenantLifecycleGuardService;
    }

    @Transactional(readOnly = true)
    public List<AllowedTenantResponse> listAllowedTenants(RequestActor actor) {
        if (actor == null) {
            return List.of();
        }
        if (actor.hasRole("PLATFORM_OWNER")) {
            return tenantSupportGrantService.listActiveGrantsForPlatformOwner(actor.userId()).stream()
                    .filter(grant -> tenantLifecycleGuardService.isTenantAccessible(grant.getTenant()))
                    .map(grant -> new AllowedTenantResponse(
                            grant.getTenant().getId().toString(),
                            grant.getTenant().getName(),
                            grant.getTenant().getSlug(),
                            "PLATFORM_SUPPORT",
                            grant.getAccessMode(),
                            grant.getExpiresAt()))
                    .toList();
        }
        return tenantMembershipRepository.findByUserExternalSubjectAndStatusOrderByCreatedAtAsc(actor.userId(), "ACTIVE").stream()
                .filter(membership -> tenantLifecycleGuardService.isTenantAccessible(membership.getTenant()))
                .map(membership -> new AllowedTenantResponse(
                        membership.getTenant().getId().toString(),
                        membership.getTenant().getName(),
                        membership.getTenant().getSlug(),
                        membership.getRole(),
                        null,
                        null))
                .toList();
    }
}
