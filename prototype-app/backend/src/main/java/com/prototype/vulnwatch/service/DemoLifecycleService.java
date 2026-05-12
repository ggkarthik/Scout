package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.DemoInvite;
import com.prototype.vulnwatch.domain.DemoRequest;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.client.ResendEmailClient;
import com.prototype.vulnwatch.dto.DemoInviteResponse;
import com.prototype.vulnwatch.dto.DemoInviteValidationResponse;
import com.prototype.vulnwatch.dto.DemoRequestCreateRequest;
import com.prototype.vulnwatch.dto.DemoRequestResponse;
import com.prototype.vulnwatch.dto.DemoStatusResponse;
import com.prototype.vulnwatch.repo.DemoInviteRepository;
import com.prototype.vulnwatch.repo.DemoRequestRepository;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class DemoLifecycleService {
    public static final String DEMO_PLAN_CODE = "DEMO";
    private static final List<String> ACTIVE_REQUEST_STATUSES = List.of("PENDING", "APPROVED", "PROVISIONED");

    private final DemoRequestRepository demoRequestRepository;
    private final DemoInviteRepository demoInviteRepository;
    private final TenantRepository tenantRepository;
    private final TenantService tenantService;
    private final IdentityAdministrationService identityAdministrationService;
    private final LocalCredentialAuthService localCredentialAuthService;
    private final DemoInviteEmailService demoInviteEmailService;
    private final AuditEventService auditEventService;
    private final SbomUploadRepository sbomUploadRepository;
    private final SecureRandom secureRandom = new SecureRandom();
    private final String appBaseUrl;

    public DemoLifecycleService(
            DemoRequestRepository demoRequestRepository,
            DemoInviteRepository demoInviteRepository,
            TenantRepository tenantRepository,
            TenantService tenantService,
            IdentityAdministrationService identityAdministrationService,
            LocalCredentialAuthService localCredentialAuthService,
            DemoInviteEmailService demoInviteEmailService,
            AuditEventService auditEventService,
            SbomUploadRepository sbomUploadRepository,
            @Value("${app.demo.app-base-url:http://localhost:5173}") String appBaseUrl
    ) {
        this.demoRequestRepository = demoRequestRepository;
        this.demoInviteRepository = demoInviteRepository;
        this.tenantRepository = tenantRepository;
        this.tenantService = tenantService;
        this.identityAdministrationService = identityAdministrationService;
        this.localCredentialAuthService = localCredentialAuthService;
        this.demoInviteEmailService = demoInviteEmailService;
        this.auditEventService = auditEventService;
        this.sbomUploadRepository = sbomUploadRepository;
        this.appBaseUrl = appBaseUrl == null || appBaseUrl.isBlank() ? "http://localhost:5173" : appBaseUrl.replaceAll("/+$", "");
    }

    @Transactional
    public DemoRequestResponse createRequest(DemoRequestCreateRequest request) {
        String email = requireText(request.email(), "email").toLowerCase();
        demoRequestRepository.findFirstByEmailIgnoreCaseAndStatusInOrderByRequestedAtDesc(email, ACTIVE_REQUEST_STATUSES)
                .ifPresent(existing -> {
                    throw new DemoAccessException("DEMO_REQUEST_EXISTS", "A demo request for this email is already in review", HttpStatus.CONFLICT);
                });
        DemoRequest demoRequest = new DemoRequest();
        demoRequest.setEmail(email);
        demoRequest.setFullName(requireText(request.fullName(), "fullName"));
        demoRequest.setCompany(requireText(request.company(), "company"));
        demoRequest.setRoleTitle(trimToNull(request.roleTitle()));
        demoRequest.setCompanySize(trimToNull(request.companySize()));
        demoRequest.setUseCase(trimToNull(request.useCase()));
        demoRequest.setNotes(trimToNull(request.notes()));
        DemoRequest saved = demoRequestRepository.save(demoRequest);
        auditEventService.record("demo.request.created", "demo_request", saved.getId().toString(), "{\"email\":\"" + email + "\"}");
        return toRequestResponse(saved);
    }

    @Transactional(readOnly = true)
    public List<DemoRequestResponse> listRequests() {
        return demoRequestRepository.findAllByOrderByRequestedAtDesc().stream()
                .map(this::toRequestResponse)
                .toList();
    }

    @Transactional
    public DemoRequestResponse approve(UUID requestId, String actor) {
        DemoRequest request = getRequest(requestId);
        if ("PROVISIONED".equalsIgnoreCase(request.getStatus())) {
            return toRequestResponse(request);
        }
        Tenant tenant = provisionTenant(request, actor);
        DemoInvite invite = deliverInvite(createInvite(request, tenant), request);
        request.setStatus("PROVISIONED");
        request.setDecidedAt(Instant.now());
        request.setDecidedBy(trimToNull(actor));
        request.setTenantId(tenant.getId());
        demoRequestRepository.save(request);
        auditEventService.record("demo.request.approved", "demo_request", request.getId().toString(),
                "{\"tenantId\":\"" + tenant.getId() + "\",\"inviteId\":\"" + invite.getId() + "\"}");
        return toRequestResponse(request);
    }

    @Transactional
    public DemoRequestResponse reject(UUID requestId, String reason, String actor) {
        DemoRequest request = getRequest(requestId);
        request.setStatus("REJECTED");
        request.setDecidedAt(Instant.now());
        request.setDecidedBy(trimToNull(actor));
        request.setRejectionReason(trimToNull(reason));
        auditEventService.record("demo.request.rejected", "demo_request", request.getId().toString(), null);
        return toRequestResponse(demoRequestRepository.save(request));
    }

    @Transactional
    public DemoInviteResponse resendInvite(UUID requestId) {
        DemoRequest request = getRequest(requestId);
        DemoInvite invite = latestInvite(requestId);
        if (invite == null) {
            if (request.getTenantId() == null) {
                throw new DemoAccessException("DEMO_INVITE_INVALID", "Demo request has not been provisioned yet", HttpStatus.BAD_REQUEST);
            }
            Tenant tenant = tenantRepository.findById(request.getTenantId())
                    .orElseThrow(() -> new IllegalArgumentException("Unknown tenant: " + request.getTenantId()));
            invite = createInvite(request, tenant);
        }
        invite = deliverInvite(invite, request);
        auditEventService.record("demo.invite.resent", "demo_invite", invite.getId().toString(), null);
        return toInviteResponse(invite);
    }

    @Transactional(readOnly = true)
    public DemoInviteValidationResponse validateInvite(String token) {
        DemoInvite invite = findInvite(token);
        return inviteValidationResponse(invite, null, null);
    }

    @Transactional
    public DemoInviteValidationResponse acceptInvite(String token) {
        DemoInvite invite = findInvite(token);
        DemoInviteValidationResponse validation = inviteValidationResponse(invite, null, null);
        if (!validation.valid()) {
            throw new DemoAccessException("DEMO_INVITE_INVALID", validation.message(), HttpStatus.BAD_REQUEST);
        }
        invite.setStatus("ACCEPTED");
        invite.setAcceptedAt(Instant.now());
        demoInviteRepository.save(invite);
        String setupToken = localCredentialAuthService.issuePasswordSetupToken(invite.getEmail());
        auditEventService.record("demo.invite.accepted", "demo_invite", invite.getId().toString(),
                "{\"tenantId\":\"" + invite.getTenant().getId() + "\"}");
        return inviteValidationResponse(invite, "Invite accepted", setupToken);
    }

    @Transactional(readOnly = true)
    public DemoStatusResponse statusForTenant(Tenant tenant) {
        boolean demo = isDemoTenant(tenant);
        Instant since = Instant.now().minus(24, ChronoUnit.HOURS);
        long uploads = sbomUploadRepository.countByTenantAndUploadedAtGreaterThanEqual(tenant, since);
        return new DemoStatusResponse(
                demo,
                tenant.getPlanCode(),
                tenant.getDemoExpiresAt(),
                daysRemaining(tenant.getDemoExpiresAt()),
                Map.of(
                        "sbomUpload", demo,
                        "liveConnectors", !demo,
                        "aiActions", !demo,
                        "exports", true
                ),
                Map.of(
                        "dailySbomUploads", uploads,
                        "maxDailySbomUploads", safeLong(tenant.getMaxDailySbomUploads()),
                        "maxDailyExposureRefreshes", safeLong(tenant.getMaxDailyExposureRefreshes()),
                        "maxExportRows", safeLong(tenant.getMaxExportRows())
                )
        );
    }

    public void assertDemoAllowsLiveConnector(Tenant tenant) {
        if (isDemoTenant(tenant)) {
            throw new DemoAccessException("DEMO_CONNECTOR_DISABLED", "Live connectors are disabled for free demo tenants", HttpStatus.FORBIDDEN);
        }
    }

    public void assertDemoAllowsAiAction(Tenant tenant) {
        if (isDemoTenant(tenant)) {
            throw new DemoAccessException("DEMO_CONNECTOR_DISABLED", "AI actions are disabled for free demo tenants", HttpStatus.FORBIDDEN);
        }
    }

    @Transactional(readOnly = true)
    public void assertCanUploadSbom(Tenant tenant) {
        if (!isDemoTenant(tenant)) {
            return;
        }
        int max = tenant.getMaxDailySbomUploads() == null ? 0 : Math.max(0, tenant.getMaxDailySbomUploads());
        long current = sbomUploadRepository.countByTenantAndUploadedAtGreaterThanEqual(tenant, Instant.now().minus(24, ChronoUnit.HOURS));
        if (current >= max) {
            throw new DemoAccessException("DEMO_QUOTA_EXCEEDED", "Demo SBOM upload limit reached for the last 24 hours", HttpStatus.TOO_MANY_REQUESTS);
        }
    }

    public boolean isDemoTenant(Tenant tenant) {
        return tenant != null && DEMO_PLAN_CODE.equalsIgnoreCase(tenant.getPlanCode());
    }

    @Scheduled(cron = "${app.demo.expiration-cron:0 10 * * * *}")
    @Transactional
    public void expireDemoTenants() {
        Instant now = Instant.now();
        for (Tenant tenant : tenantRepository.findByPlanCodeIgnoreCaseAndStatusIgnoreCaseAndDemoExpiresAtBefore(DEMO_PLAN_CODE, "ACTIVE", now)) {
            tenant.setStatus("SUSPENDED");
            tenant.setSuspendedAt(now);
            tenant.setUpdatedAt(now);
            tenantRepository.save(tenant);
            auditEventService.record("demo.tenant.expired", "tenant", tenant.getId().toString(), null);
        }
    }

    private Tenant provisionTenant(DemoRequest request, String actor) {
        String slug = normalizeSlug(request.getCompany());
        String candidate = slug;
        int suffix = 2;
        while (tenantRepository.findBySlugIgnoreCase(candidate).isPresent()) {
            candidate = slug + "-" + suffix++;
        }
        Tenant tenant = tenantService.createTenant(request.getCompany(), candidate, DEMO_PLAN_CODE, "demo-request:" + request.getId());
        tenant.setDemoExpiresAt(Instant.now().plus(7, ChronoUnit.DAYS));
        tenant.setDemoCreatedBy(trimToNull(actor));
        tenant.setDemoSource("REQUEST_REVIEW");
        tenant.setMaxConnectorCount(0);
        tenant.setMaxServiceAccountCount(0);
        tenant.setMaxDailySbomUploads(5);
        tenant.setMaxDailyExposureRefreshes(3);
        tenant.setMaxExportRows(1000);
        Tenant saved = tenantRepository.save(tenant);
        identityAdministrationService.addMember(saved.getId(), request.getEmail(), request.getEmail(), request.getFullName(), "TENANT_ADMIN");
        return saved;
    }

    private DemoInvite createInvite(DemoRequest request, Tenant tenant) {
        DemoInvite invite = new DemoInvite();
        invite.setRequest(request);
        invite.setTenant(tenant);
        invite.setEmail(request.getEmail());
        invite.setToken(newToken());
        invite.setStatus("READY");
        invite.setExpiresAt(Instant.now().plus(7, ChronoUnit.DAYS));
        return demoInviteRepository.save(invite);
    }

    private DemoInvite deliverInvite(DemoInvite invite, DemoRequest request) {
        ResendEmailClient.DeliveryResult deliveryResult = demoInviteEmailService.sendInvite(request, invite);
        if (deliveryResult.state() == ResendEmailClient.DeliveryState.SENT) {
            invite.setStatus("SENT");
            invite.setLastSentAt(Instant.now());
            auditEventService.record("demo.invite.email.sent", "demo_invite", invite.getId().toString(), null);
        } else if (deliveryResult.state() == ResendEmailClient.DeliveryState.SKIPPED) {
            invite.setStatus("READY");
            auditEventService.record("demo.invite.email.skipped", "demo_invite", invite.getId().toString(), null);
        } else {
            invite.setStatus("DELIVERY_FAILED");
            auditEventService.record("demo.invite.email.failed", "demo_invite", invite.getId().toString(), null);
        }
        return demoInviteRepository.save(invite);
    }

    private DemoRequest getRequest(UUID requestId) {
        return demoRequestRepository.findById(requestId)
                .orElseThrow(() -> new DemoAccessException("DEMO_INVITE_INVALID", "Demo request not found", HttpStatus.NOT_FOUND));
    }

    private DemoInvite findInvite(String token) {
        return demoInviteRepository.findByToken(requireText(token, "token"))
                .orElseThrow(() -> new DemoAccessException("DEMO_INVITE_INVALID", "Demo invite not found", HttpStatus.NOT_FOUND));
    }

    private DemoInviteValidationResponse inviteValidationResponse(DemoInvite invite, String overrideMessage, String setupToken) {
        Instant now = Instant.now();
        Tenant tenant = invite.getTenant();
        boolean tenantExpired = tenant.getDemoExpiresAt() != null && !tenant.getDemoExpiresAt().isAfter(now);
        boolean inviteExpired = !invite.getExpiresAt().isAfter(now);
        boolean accepted = invite.getAcceptedAt() != null || "ACCEPTED".equalsIgnoreCase(invite.getStatus());
        boolean valid = !tenantExpired && !inviteExpired && !accepted && "ACTIVE".equalsIgnoreCase(tenant.getStatus());
        String status = tenantExpired ? "TENANT_EXPIRED" : inviteExpired ? "INVITE_EXPIRED" : accepted ? "ACCEPTED" : valid ? "VALID" : "INVALID";
        String message = overrideMessage != null ? overrideMessage : switch (status) {
            case "VALID" -> "Invite is ready";
            case "ACCEPTED" -> "Invite has already been accepted";
            case "TENANT_EXPIRED" -> "Demo tenant has expired";
            case "INVITE_EXPIRED" -> "Demo invite has expired";
            default -> "Demo invite is not active";
        };
        return new DemoInviteValidationResponse(
                valid,
                status,
                invite.getEmail(),
                tenant.getId(),
                tenant.getName(),
                tenant.getDemoExpiresAt(),
                invite.getExpiresAt(),
                appBaseUrl + "/login?invite=" + invite.getToken(),
                message,
                setupToken);
    }

    private DemoRequestResponse toRequestResponse(DemoRequest request) {
        return new DemoRequestResponse(
                request.getId(),
                request.getEmail(),
                request.getFullName(),
                request.getCompany(),
                request.getRoleTitle(),
                request.getCompanySize(),
                request.getUseCase(),
                request.getNotes(),
                request.getStatus(),
                request.getRequestedAt(),
                request.getDecidedAt(),
                request.getDecidedBy(),
                request.getRejectionReason(),
                request.getTenantId(),
                latestInviteResponse(request.getId())
        );
    }

    private DemoInviteResponse latestInviteResponse(UUID requestId) {
        DemoInvite invite = latestInvite(requestId);
        return invite == null ? null : toInviteResponse(invite);
    }

    private DemoInvite latestInvite(UUID requestId) {
        return demoInviteRepository.findByRequest_IdOrderByCreatedAtDesc(requestId).stream()
                .max(Comparator.comparing(DemoInvite::getCreatedAt))
                .orElse(null);
    }

    private DemoInviteResponse toInviteResponse(DemoInvite invite) {
        return new DemoInviteResponse(
                invite.getId(),
                invite.getRequest() == null ? null : invite.getRequest().getId(),
                invite.getTenant().getId(),
                invite.getTenant().getName(),
                invite.getEmail(),
                invite.getStatus(),
                invite.getExpiresAt(),
                invite.getAcceptedAt(),
                invite.getLastSentAt(),
                appBaseUrl + "/invite/" + invite.getToken()
        );
    }

    private Long daysRemaining(Instant expiresAt) {
        if (expiresAt == null) {
            return null;
        }
        long hours = Instant.now().until(expiresAt, ChronoUnit.HOURS);
        return Math.max(0, (hours + 23) / 24);
    }

    private long safeLong(Integer value) {
        return value == null ? 0L : value.longValue();
    }

    private String newToken() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String normalizeSlug(String value) {
        String slug = requireText(value, "company")
                .toLowerCase()
                .replaceAll("[^a-z0-9]+", "-")
                .replaceAll("(^-|-$)", "");
        return slug.isBlank() ? "demo" : slug;
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
}
