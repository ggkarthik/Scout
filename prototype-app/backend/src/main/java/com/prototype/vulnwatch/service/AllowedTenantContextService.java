package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.dto.AllowedTenantResponse;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AllowedTenantContextService {

    private final TenantRepository tenantRepository;
    private final TenantMembershipRepository tenantMembershipRepository;

    public AllowedTenantContextService(
            TenantRepository tenantRepository,
            TenantMembershipRepository tenantMembershipRepository
    ) {
        this.tenantRepository = tenantRepository;
        this.tenantMembershipRepository = tenantMembershipRepository;
    }

    @Transactional(readOnly = true)
    public List<AllowedTenantResponse> listAllowedTenants(RequestActor actor) {
        if (actor == null) {
            return List.of();
        }
        if (actor.hasRole("PLATFORM_OWNER")) {
            return tenantRepository.findAllByOrderByCreatedAtAsc().stream()
                    .map(tenant -> new AllowedTenantResponse(
                            tenant.getId().toString(),
                            tenant.getName(),
                            tenant.getSlug(),
                            "PLATFORM_OWNER"))
                    .toList();
        }
        return tenantMembershipRepository.findByUserExternalSubjectAndStatusOrderByCreatedAtAsc(actor.userId(), "ACTIVE").stream()
                .map(membership -> new AllowedTenantResponse(
                        membership.getTenant().getId().toString(),
                        membership.getTenant().getName(),
                        membership.getTenant().getSlug(),
                        membership.getRole()))
                .toList();
    }
}
