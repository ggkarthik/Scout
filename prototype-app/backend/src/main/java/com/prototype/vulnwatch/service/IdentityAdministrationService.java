package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.AuditEvent;
import com.prototype.vulnwatch.domain.ServiceAccount;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantMembership;
import com.prototype.vulnwatch.domain.TenantUserInvite;
import com.prototype.vulnwatch.dto.PlatformUserResponse;
import com.prototype.vulnwatch.dto.PlatformUserSetupLinkResponse;
import com.prototype.vulnwatch.repo.AuditEventRepository;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.ServiceAccountRepository;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.repo.TenantUserInviteRepository;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

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
    private final LocalCredentialAuthService localCredentialAuthService;
    private final AuditEventRepository auditEventRepository;
    private final String appBaseUrl;
    private TransactionTemplate readTransactionTemplate;
    private TransactionTemplate writeTransactionTemplate;

    public IdentityAdministrationService(
            AppUserRepository userRepository,
            TenantRepository tenantRepository,
            TenantMembershipRepository membershipRepository,
            TenantUserInviteRepository tenantUserInviteRepository,
            ServiceAccountRepository serviceAccountRepository,
            AuditEventRepository auditEventRepository,
            TenantQuotaService tenantQuotaService,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            AppUserGlobalRoleService appUserGlobalRoleService,
            LocalCredentialAuthService localCredentialAuthService,
            @Value("${app.demo.app-base-url:http://localhost:5173}") String appBaseUrl
    ) {
        this.userRepository = userRepository;
        this.tenantRepository = tenantRepository;
        this.membershipRepository = membershipRepository;
        this.tenantUserInviteRepository = tenantUserInviteRepository;
        this.serviceAccountRepository = serviceAccountRepository;
        this.auditEventRepository = auditEventRepository;
        this.tenantQuotaService = tenantQuotaService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.appUserGlobalRoleService = appUserGlobalRoleService;
        this.localCredentialAuthService = localCredentialAuthService;
        this.appBaseUrl = appBaseUrl == null || appBaseUrl.isBlank() ? "http://localhost:5173" : appBaseUrl.replaceAll("/+$", "");
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setTransactionManager(PlatformTransactionManager transactionManager) {
        if (transactionManager == null) {
            this.readTransactionTemplate = null;
            this.writeTransactionTemplate = null;
            return;
        }
        this.readTransactionTemplate = new TransactionTemplate(transactionManager);
        this.readTransactionTemplate.setReadOnly(true);
        this.readTransactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.writeTransactionTemplate = new TransactionTemplate(transactionManager);
        this.writeTransactionTemplate.setReadOnly(false);
        this.writeTransactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
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
        AppUser user = loadOrCreateEligibleLockedUser(tenantId, subject, email, displayName);
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
        Map<String, PlatformUserAuditSummary> auditByTargetId = latestPlatformUserAuditByTargetId(users);
        Map<UUID, java.util.Set<String>> rolesByUserId = appUserGlobalRoleService.rolesByUserIds(
                users.stream().map(AppUser::getId).toList()
        );
        return users.stream()
                .map(user -> toPlatformUserResponse(
                        user,
                        rolesByUserId.getOrDefault(user.getId(), java.util.Set.of()),
                        auditByTargetId.getOrDefault(user.getId().toString(), PlatformUserAuditSummary.EMPTY)))
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
        return toPlatformUserResponse(
                user,
                appUserGlobalRoleService.rolesForUser(user.getId()),
                latestPlatformUserAuditByTargetId(List.of(user)).getOrDefault(user.getId().toString(), PlatformUserAuditSummary.EMPTY)
        );
    }

    @Transactional
    public void revokePlatformUserRole(UUID userId, String role) {
        AppUser user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown user: " + userId));
        appUserGlobalRoleService.revokeRole(user, normalizeRole(role));
    }

    @Transactional
    public PlatformUserSetupLinkResponse issuePlatformUserSetupLink(UUID userId) {
        AppUser user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown user: " + userId));
        if (!user.isPlatformOwner()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Password setup is only available for platform users");
        }
        if (!hasText(user.getEmail())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Platform user must have an email before password setup can be issued");
        }
        String setupToken = localCredentialAuthService.issuePasswordSetupToken(user.getExternalSubject());
        return new PlatformUserSetupLinkResponse(
                user.getId(),
                user.getEmail(),
                appBaseUrl + "/login?setup=" + setupToken + "&email=" + URLEncoder.encode(user.getEmail(), StandardCharsets.UTF_8)
        );
    }

    public List<ServiceAccount> listServiceAccounts(UUID tenantId) {
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown tenant: " + tenantId));
        return tenantSchemaExecutionService.run(tenant, () -> executeRead(serviceAccountRepository::findAllByOrderByCreatedAtAsc));
    }

    public ServiceAccount createServiceAccount(UUID tenantId, String name, String keyId, String role) {
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown tenant: " + tenantId));
        tenantQuotaService.assertCanCreateServiceAccount(tenant);
        return tenantSchemaExecutionService.run(tenant, () -> executeWrite(() -> {
            ServiceAccount account = new ServiceAccount();
            account.setTenant(tenant);
            account.setName(requireText(name, "name"));
            account.setKeyId(requireText(keyId, "keyId"));
            account.setRole(normalizeRole(role));
            return serviceAccountRepository.save(account);
        }));
    }

    public void deleteServiceAccount(UUID tenantId, UUID accountId) {
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown tenant: " + tenantId));
        tenantSchemaExecutionService.run(tenant, () -> executeWrite(() -> {
            ServiceAccount account = serviceAccountRepository.findById(accountId)
                    .orElseThrow(() -> new IllegalArgumentException("Unknown service account: " + accountId));
            if (account.getTenant() == null || !tenantId.equals(account.getTenant().getId())) {
                throw new IllegalArgumentException("Service account does not belong to tenant: " + tenantId);
            }
            serviceAccountRepository.delete(account);
            return null;
        }));
    }

    public ServiceAccount deactivateServiceAccount(UUID tenantId, UUID accountId) {
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown tenant: " + tenantId));
        return tenantSchemaExecutionService.run(tenant, () -> executeWrite(() -> {
            ServiceAccount account = serviceAccountRepository.findById(accountId)
                    .orElseThrow(() -> new IllegalArgumentException("Unknown service account: " + accountId));
            if (account.getTenant() == null || !tenantId.equals(account.getTenant().getId())) {
                throw new IllegalArgumentException("Service account does not belong to tenant: " + tenantId);
            }
            account.setStatus("PAUSED");
            account.setUpdatedAt(Instant.now());
            return serviceAccountRepository.save(account);
        }));
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

    @Transactional(readOnly = true)
    public List<TenantMembership> listActiveMemberships(String subject) {
        return membershipRepository.findByUserExternalSubjectAndStatusOrderByCreatedAtAsc(
                requireText(subject, "subject"),
                "ACTIVE"
        );
    }

    @Transactional
    public AppUser loadOrCreateLockedUser(String subject, String email, String displayName) {
        String normalizedSubject = requireText(subject, "subject");
        AppUser existing = userRepository.findByExternalSubject(normalizedSubject).orElse(null);
        if (existing == null) {
            try {
                existing = userRepository.saveAndFlush(createUser(normalizedSubject, email, displayName));
            } catch (DataIntegrityViolationException conflict) {
                existing = userRepository.findByExternalSubject(normalizedSubject)
                        .orElseThrow(() -> conflict);
            }
        }
        UUID userId = existing.getId();
        return userRepository.findByIdForUpdate(userId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown user: " + userId));
    }

    @Transactional
    public AppUser loadOrCreateEligibleLockedUser(UUID tenantId, String subject, String email, String displayName) {
        AppUser user = loadOrCreateLockedUser(subject, email, displayName);
        assertEligibleForTenantMembership(user, tenantId);
        return user;
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
        AppUser user = loadOrCreateEligibleLockedUser(tenantId, normalizedSubject, email, displayName);
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

    public void assertEligibleForTenantMembership(AppUser user, UUID tenantId) {
        if (user.isPlatformOwner()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Platform-owner identities cannot be added to tenant memberships");
        }
        List<TenantMembership> activeMemberships = listActiveMemberships(user.getExternalSubject());
        boolean hasOtherTenantMembership = activeMemberships.stream()
                .map(TenantMembership::getTenant)
                .filter(java.util.Objects::nonNull)
                .map(Tenant::getId)
                .anyMatch(existingTenantId -> tenantId == null || !tenantId.equals(existingTenantId));
        if (hasOtherTenantMembership) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "This user already has active access to another tenant");
        }
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

    private <T> T executeRead(java.util.function.Supplier<T> work) {
        if (readTransactionTemplate == null) {
            return work.get();
        }
        T result = readTransactionTemplate.execute(status -> work.get());
        return result == null ? work.get() : result;
    }

    private <T> T executeWrite(java.util.function.Supplier<T> work) {
        if (writeTransactionTemplate == null) {
            return work.get();
        }
        return writeTransactionTemplate.execute(status -> work.get());
    }

    private PlatformUserResponse toPlatformUserResponse(AppUser user, java.util.Set<String> roles, PlatformUserAuditSummary auditSummary) {
        return new PlatformUserResponse(
                user.getId(),
                user.getExternalSubject(),
                user.getEmail(),
                user.getDisplayName(),
                user.getStatus(),
                roles.stream().sorted().toList(),
                user.getPasswordSetAt() != null,
                user.getPasswordSetupTokenHash() != null
                        && user.getPasswordSetupTokenExpiresAt() != null
                        && user.getPasswordSetupTokenExpiresAt().isAfter(Instant.now()),
                user.getPasswordSetAt(),
                auditSummary.lastSetupIssuedAt(),
                auditSummary.lastSetupCompletedAt(),
                user.getLastSeenAt(),
                user.getCreatedAt()
        );
    }

    private Map<String, PlatformUserAuditSummary> latestPlatformUserAuditByTargetId(List<AppUser> users) {
        if (users == null || users.isEmpty()) {
            return java.util.Map.of();
        }
        List<String> targetIds = users.stream()
                .map(AppUser::getId)
                .map(UUID::toString)
                .toList();
        List<AuditEvent> events = auditEventRepository.findByTargetTypeAndTargetIdInAndActionInOrderByOccurredAtDesc(
                "app_user",
                targetIds,
                List.of("platform.user.setup_issued", "platform.user.setup_completed")
        );
        java.util.Map<String, PlatformUserAuditSummary> summaries = new java.util.LinkedHashMap<>();
        for (AuditEvent event : events) {
            if (event.getTargetId() == null) {
                continue;
            }
            PlatformUserAuditSummary current = summaries.getOrDefault(event.getTargetId(), PlatformUserAuditSummary.EMPTY);
            if ("platform.user.setup_issued".equals(event.getAction()) && current.lastSetupIssuedAt() == null) {
                summaries.put(event.getTargetId(), current.withLastSetupIssuedAt(event.getOccurredAt()));
            } else if ("platform.user.setup_completed".equals(event.getAction()) && current.lastSetupCompletedAt() == null) {
                summaries.put(event.getTargetId(), current.withLastSetupCompletedAt(event.getOccurredAt()));
            }
        }
        return summaries;
    }

    private record PlatformUserAuditSummary(
            Instant lastSetupIssuedAt,
            Instant lastSetupCompletedAt
    ) {
        private static final PlatformUserAuditSummary EMPTY = new PlatformUserAuditSummary(null, null);

        private PlatformUserAuditSummary withLastSetupIssuedAt(Instant occurredAt) {
            return new PlatformUserAuditSummary(occurredAt, lastSetupCompletedAt);
        }

        private PlatformUserAuditSummary withLastSetupCompletedAt(Instant occurredAt) {
            return new PlatformUserAuditSummary(lastSetupIssuedAt, occurredAt);
        }
    }
}
