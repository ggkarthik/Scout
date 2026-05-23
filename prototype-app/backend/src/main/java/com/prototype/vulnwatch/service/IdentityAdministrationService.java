package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.ServiceAccount;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantMembership;
import com.prototype.vulnwatch.dto.PlatformUserResponse;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.ServiceAccountRepository;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class IdentityAdministrationService {

    private final AppUserRepository userRepository;
    private final TenantRepository tenantRepository;
    private final TenantMembershipRepository membershipRepository;
    private final ServiceAccountRepository serviceAccountRepository;
    private final TenantQuotaService tenantQuotaService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final AppUserGlobalRoleService appUserGlobalRoleService;

    public IdentityAdministrationService(
            AppUserRepository userRepository,
            TenantRepository tenantRepository,
            TenantMembershipRepository membershipRepository,
            ServiceAccountRepository serviceAccountRepository,
            TenantQuotaService tenantQuotaService,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            AppUserGlobalRoleService appUserGlobalRoleService
    ) {
        this.userRepository = userRepository;
        this.tenantRepository = tenantRepository;
        this.membershipRepository = membershipRepository;
        this.serviceAccountRepository = serviceAccountRepository;
        this.tenantQuotaService = tenantQuotaService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.appUserGlobalRoleService = appUserGlobalRoleService;
    }

    @Transactional(readOnly = true)
    public List<TenantMembership> listMembers(UUID tenantId) {
        return membershipRepository.findByTenantIdOrderByCreatedAtAsc(tenantId);
    }

    @Transactional
    public TenantMembership addMember(UUID tenantId, String subject, String email, String displayName, String role) {
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown tenant: " + tenantId));
        AppUser user = userRepository.findByExternalSubject(requireText(subject, "subject"))
                .orElseGet(() -> createUser(subject, email, displayName));
        user.setEmail(trimToNull(email));
        user.setDisplayName(trimToNull(displayName));
        user.setUpdatedAt(Instant.now());
        userRepository.save(user);

        TenantMembership membership = new TenantMembership();
        membership.setTenant(tenant);
        membership.setUser(user);
        membership.setRole(normalizeRole(role));
        return membershipRepository.save(membership);
    }

    @Transactional(readOnly = true)
    public List<PlatformUserResponse> listPlatformUsers() {
        List<AppUser> users = userRepository.findAll().stream()
                .filter(AppUser::isPlatformOwner)
                .toList();
        Map<UUID, java.util.Set<String>> rolesByUserId = appUserGlobalRoleService.rolesByUserIds(
                users.stream().map(AppUser::getId).toList()
        );
        return users.stream()
                .map(user -> toPlatformUserResponse(user, rolesByUserId.getOrDefault(user.getId(), java.util.Set.of())))
                .sorted(Comparator.comparing(PlatformUserResponse::createdAt))
                .toList();
    }

    @Transactional
    public PlatformUserResponse upsertPlatformUserRole(String subject, String email, String displayName, String role) {
        String normalizedSubject = requireText(subject, "subject");
        AppUser user = userRepository.findByExternalSubject(normalizedSubject)
                .orElseGet(() -> createUser(normalizedSubject, email, displayName));
        user.setEmail(trimToNull(email));
        user.setDisplayName(trimToNull(displayName));
        user.setStatus("ACTIVE");
        user.setUpdatedAt(Instant.now());
        userRepository.save(user);
        appUserGlobalRoleService.ensureRole(user, normalizeRole(role));
        return toPlatformUserResponse(user, appUserGlobalRoleService.rolesForUser(user.getId()));
    }

    @Transactional
    public void revokePlatformUserRole(UUID userId, String role) {
        AppUser user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown user: " + userId));
        appUserGlobalRoleService.revokeRole(user, normalizeRole(role));
    }

    @Transactional(readOnly = true)
    public List<ServiceAccount> listServiceAccounts(UUID tenantId) {
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown tenant: " + tenantId));
        return tenantSchemaExecutionService.run(tenant, serviceAccountRepository::findAllByOrderByCreatedAtAsc);
    }

    @Transactional
    public ServiceAccount createServiceAccount(UUID tenantId, String name, String keyId, String role) {
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown tenant: " + tenantId));
        tenantQuotaService.assertCanCreateServiceAccount(tenant);
        ServiceAccount account = new ServiceAccount();
        account.setTenant(tenant);
        account.setName(requireText(name, "name"));
        account.setKeyId(requireText(keyId, "keyId"));
        account.setRole(normalizeRole(role));
        return serviceAccountRepository.save(account);
    }

    private AppUser createUser(String subject, String email, String displayName) {
        AppUser user = new AppUser();
        user.setExternalSubject(requireText(subject, "subject"));
        user.setEmail(trimToNull(email));
        user.setDisplayName(trimToNull(displayName));
        return user;
    }

    private String normalizeRole(String role) {
        return requireText(role, "role").trim().toUpperCase(Locale.ROOT).replace('-', '_').replace(' ', '_');
    }

    private String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value.trim();
    }

    private String trimToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private PlatformUserResponse toPlatformUserResponse(AppUser user, java.util.Set<String> roles) {
        return new PlatformUserResponse(
                user.getId(),
                user.getExternalSubject(),
                user.getEmail(),
                user.getDisplayName(),
                user.getStatus(),
                roles.stream().sorted().toList(),
                user.getLastSeenAt(),
                user.getCreatedAt()
        );
    }
}
