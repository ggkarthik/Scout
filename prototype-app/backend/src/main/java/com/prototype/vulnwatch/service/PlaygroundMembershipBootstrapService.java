package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.config.PlaygroundMembershipProperties;
import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantMembership;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import java.util.Locale;
import java.util.Set;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Service;

@Service
public class PlaygroundMembershipBootstrapService {
    private static final Set<String> ALLOWED_ROLES = Set.of(
            "TENANT_ADMIN", "INVENTORY_ADMIN", "SECURITY_ANALYST", "READ_ONLY_AUDITOR");

    private final PlaygroundMembershipProperties properties;
    private final TenantRepository tenantRepository;
    private final AppUserRepository userRepository;
    private final TenantMembershipRepository membershipRepository;
    private final AppUserGlobalRoleService globalRoleService;
    private final AuditEventService auditEventService;
    private final TenantWorkRunner tenantWorkRunner;

    public PlaygroundMembershipBootstrapService(
            PlaygroundMembershipProperties properties,
            TenantRepository tenantRepository,
            AppUserRepository userRepository,
            TenantMembershipRepository membershipRepository,
            AppUserGlobalRoleService globalRoleService,
            AuditEventService auditEventService,
            TenantWorkRunner tenantWorkRunner
    ) {
        this.properties = properties;
        this.tenantRepository = tenantRepository;
        this.userRepository = userRepository;
        this.membershipRepository = membershipRepository;
        this.globalRoleService = globalRoleService;
        this.auditEventService = auditEventService;
        this.tenantWorkRunner = tenantWorkRunner;
    }

    @EventListener(ApplicationReadyEvent.class)
    @Order(20)
    public void reconcile() {
        TenantContext.runAsPlatform(this::reconcileInPlatformScope);
    }

    private void reconcileInPlatformScope() {
        Set<String> configured = properties.isEnabled()
                ? properties.getSubjects().stream().filter(this::hasText)
                        .map(String::trim).collect(java.util.stream.Collectors.toSet())
                : Set.of();
        String role = normalizeRole(properties.getRole());
        if (!ALLOWED_ROLES.contains(role)) {
            throw new IllegalStateException("Unsupported playground membership role: " + role);
        }

        Tenant playground = null;
        if (properties.isEnabled()) {
            playground = tenantRepository.findBySlugIgnoreCase(TenantAccessResolutionService.PLAYGROUND_SLUG)
                    .orElseThrow(() -> new IllegalStateException("Default playground tenant is not registered"));
            if (!"ACTIVE".equalsIgnoreCase(playground.getStatus())) {
                throw new IllegalStateException("Default playground tenant must be ACTIVE");
            }
        }

        for (String subject : configured) {
            AppUser user = userRepository.findByExternalSubject(subject)
                    .or(() -> userRepository.findByEmailIgnoreCase(subject))
                    .orElseThrow(() -> new IllegalStateException("Configured playground subject is not registered: " + subject));
            if (!"ACTIVE".equalsIgnoreCase(user.getStatus())
                    || !globalRoleService.rolesForUser(user.getId()).contains("PLATFORM_OWNER")) {
                throw new IllegalStateException("Configured playground subject must be an active platform owner: " + subject);
            }
            var existingMembership = membershipRepository
                    .findFirstByUserExternalSubjectAndTenantId(user.getExternalSubject(), playground.getId());
            if (existingMembership.isPresent()
                    && !TenantAccessResolutionService.PLAYGROUND_PROVENANCE.equalsIgnoreCase(
                            existingMembership.get().getProvenance())) {
                throw new IllegalStateException(
                        "Configured playground subject already has a manually managed membership: " + subject);
            }
            boolean created = existingMembership.isEmpty();
            TenantMembership membership = existingMembership.orElseGet(TenantMembership::new);
            String priorStatus = membership.getStatus();
            String priorRole = membership.getRole();
            membership.setTenant(playground);
            membership.setUser(user);
            membership.setRole(role);
            membership.setStatus("ACTIVE");
            membership.setProvenance(TenantAccessResolutionService.PLAYGROUND_PROVENANCE);
            membership.setUpdatedAt(Instant.now());
            TenantMembership membershipToSave = membership;
            String action = created
                    ? "playground.membership.created"
                    : (!"ACTIVE".equalsIgnoreCase(priorStatus) ? "playground.membership.reactivated"
                    : (!role.equalsIgnoreCase(priorRole) ? "playground.membership.role_changed" : null));
            tenantWorkRunner.runScoped(playground, () -> {
                TenantMembership savedMembership = membershipRepository.save(membershipToSave);
                if (action != null) {
                    audit(action, savedMembership);
                }
            });
        }

        for (TenantMembership membership : membershipRepository
                .findByProvenance(TenantAccessResolutionService.PLAYGROUND_PROVENANCE)) {
            String subject = membership.getUser().getExternalSubject();
            if (!configured.contains(subject) && "ACTIVE".equalsIgnoreCase(membership.getStatus())) {
                tenantWorkRunner.runScoped(membership.getTenant(), () -> {
                    membership.setStatus("SUSPENDED");
                    membership.setUpdatedAt(Instant.now());
                    TenantMembership savedMembership = membershipRepository.save(membership);
                    audit("playground.membership.suspended", savedMembership);
                });
            }
        }
    }

    private void audit(String action, TenantMembership membership) {
        auditEventService.recordExplicitActor(
                membership.getTenant().getId(),
                "system:playground-bootstrap",
                "PLATFORM_OWNER",
                action,
                "tenant_membership",
                membership.getId().toString(),
                "{\"subject\":\"" + membership.getUser().getExternalSubject() + "\",\"role\":\"" + membership.getRole() + "\"}",
                "SUCCESS");
    }

    private String normalizeRole(String value) {
        return value == null ? "TENANT_ADMIN" : value.trim().toUpperCase(Locale.ROOT)
                .replace('-', '_').replace(' ', '_').replaceFirst("^ROLE_", "");
    }

    private boolean hasText(String value) { return value != null && !value.isBlank(); }
}
