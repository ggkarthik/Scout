package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.ServiceAccount;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantMembership;
import com.prototype.vulnwatch.domain.TenantUserInvite;
import com.prototype.vulnwatch.dto.PlatformUserResponse;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.ServiceAccountRepository;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.repo.TenantUserInviteRepository;
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
    private final TenantUserInviteRepository tenantUserInviteRepository;
    private final ServiceAccountRepository serviceAccountRepository;
    private final TenantQuotaService tenantQuotaService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final AppUserGlobalRoleService appUserGlobalRoleService;

    public IdentityAdministrationService(
            AppUserRepository userRepository,
            TenantRepository tenantRepository,
            TenantMembershipRepository membershipRepository,
            TenantUserInviteRepository tenantUserInviteRepository,
            ServiceAccountRepository serviceAccountRepository,
            TenantQuotaService tenantQuotaService,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            AppUserGlobalRoleService appUserGlobalRoleService
    ) {
        this.userRepository = userRepository;
        this.tenantRepository = tenantRepository;
        this.membershipRepository = membershipRepository;
        this.tenantUserInviteRepository = tenantUserInviteRepository;
        this.serviceAccountRepository = serviceAccountRepository;
        this.tenantQuotaService = tenantQuotaService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.appUserGlobalRoleService = appUserGlobalRoleService;
    }

    @Transactional(readOnly = true)
    public List<TenantMembership> listMembers(UUID tenantId) {
        return membershipRepository.findByTenantIdOrderByCreatedAtAsc(tenantId);
    }

    @Transactional(readOnly = true)
    public TenantMembership findMember(UUID tenantId, UUID memberId) {
        TenantMembership membership = membershipRepository.findById(memberId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown membership: " + memberId));
        if (membership.getTenant() == null || !tenantId.equals(membership.getTenant().getId())) {
            throw new IllegalArgumentException("Membership does not belong to tenant: " + tenantId);
        }
        return membership;
    }

    @Transactional(readOnly = true)
    public List<TenantUserInvite> listInvites(UUID tenantId) {
        return tenantUserInviteRepository.findByTenantIdOrderByCreatedAtDesc(tenantId);
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

    @Transactional
    public TenantMembership updateMember(UUID tenantId, UUID memberId, String role, String status) {
        TenantMembership membership = findMember(tenantId, memberId);
        if (hasText(role)) {
            membership.setRole(normalizeRole(role));
        }
        if (hasText(status)) {
            membership.setStatus(normalizeStatus(status));
        }
        membership.setUpdatedAt(Instant.now());
        return membershipRepository.save(membership);
    }

    @Transactional
    public void removeMember(UUID tenantId, UUID memberId) {
        TenantMembership membership = findMember(tenantId, memberId);
        membershipRepository.delete(membership);
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

    @Transactional
    public void deleteServiceAccount(UUID tenantId, UUID accountId) {
        ServiceAccount account = serviceAccountRepository.findById(accountId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown service account: " + accountId));
        if (account.getTenant() == null || !tenantId.equals(account.getTenant().getId())) {
            throw new IllegalArgumentException("Service account does not belong to tenant: " + tenantId);
        }
        serviceAccountRepository.delete(account);
    }

    @Transactional
    public ServiceAccount deactivateServiceAccount(UUID tenantId, UUID accountId) {
        ServiceAccount account = serviceAccountRepository.findById(accountId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown service account: " + accountId));
        if (account.getTenant() == null || !tenantId.equals(account.getTenant().getId())) {
            throw new IllegalArgumentException("Service account does not belong to tenant: " + tenantId);
        }
        account.setStatus("PAUSED");
        account.setUpdatedAt(Instant.now());
        return serviceAccountRepository.save(account);
    }

    @Transactional
    public TenantUserInvite saveInvite(TenantUserInvite invite) {
        invite.setUpdatedAt(Instant.now());
        return tenantUserInviteRepository.save(invite);
    }

    @Transactional(readOnly = true)
    public TenantUserInvite findInvite(UUID tenantId, UUID inviteId) {
        return tenantUserInviteRepository.findByIdAndTenantId(inviteId, tenantId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown invite: " + inviteId));
    }

    @Transactional(readOnly = true)
    public TenantUserInvite findInviteByToken(String token) {
        return tenantUserInviteRepository.findByToken(requireText(token, "token"))
                .orElseThrow(() -> new IllegalArgumentException("Invite not found"));
    }

    @Transactional(readOnly = true)
    public boolean hasOpenInvite(UUID tenantId, String email) {
        return tenantUserInviteRepository.findFirstByTenantIdAndEmailIgnoreCaseAndStatusInOrderByCreatedAtDesc(
                tenantId,
                requireText(email, "email"),
                List.of("READY", "SENT", "DELIVERY_ERROR")
        ).isPresent();
    }

    @Transactional(readOnly = true)
    public boolean hasActiveMembership(UUID tenantId, String subject) {
        return membershipRepository.findFirstByUserExternalSubjectAndTenantIdAndStatus(
                requireText(subject, "subject"),
                tenantId,
                "ACTIVE"
        ).isPresent();
    }

    @Transactional
    public TenantMembership activateInvitedMembership(
            UUID tenantId,
            String subject,
            String email,
            String displayName,
            String role,
            AppUser invitedBy
    ) {
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown tenant: " + tenantId));
        String normalizedSubject = requireText(subject, "subject");
        AppUser user = userRepository.findByExternalSubject(normalizedSubject)
                .orElseGet(() -> createUser(normalizedSubject, email, displayName));
        user.setEmail(trimToNull(email));
        user.setDisplayName(trimToNull(displayName));
        user.setStatus("ACTIVE");
        user.setUpdatedAt(Instant.now());
        userRepository.save(user);

        TenantMembership membership = membershipRepository
                .findFirstByUserExternalSubjectAndTenantId(normalizedSubject, tenantId)
                .orElseGet(() -> {
                    TenantMembership created = new TenantMembership();
                    created.setTenant(tenant);
                    created.setUser(user);
                    created.setInvitedBy(invitedBy);
                    created.setRole(normalizeRole(role));
                    created.setStatus("ACTIVE");
                    return created;
                });
        membership.setTenant(tenant);
        membership.setUser(user);
        membership.setInvitedBy(invitedBy);
        membership.setRole(normalizeRole(role));
        membership.setStatus("ACTIVE");
        membership.setUpdatedAt(Instant.now());
        return membershipRepository.save(membership);
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

    private String normalizeStatus(String status) {
        return requireText(status, "status").trim().toUpperCase(Locale.ROOT).replace('-', '_').replace(' ', '_');
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

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
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
