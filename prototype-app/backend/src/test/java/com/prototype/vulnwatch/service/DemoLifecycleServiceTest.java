package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.client.ResendEmailClient;
import com.prototype.vulnwatch.domain.DemoInvite;
import com.prototype.vulnwatch.domain.DemoRequest;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.DemoInviteResponse;
import com.prototype.vulnwatch.dto.DemoRequestResponse;
import com.prototype.vulnwatch.repo.DemoInviteRepository;
import com.prototype.vulnwatch.repo.DemoRequestRepository;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class DemoLifecycleServiceTest {

    @Mock
    private DemoRequestRepository demoRequestRepository;
    @Mock
    private DemoInviteRepository demoInviteRepository;
    @Mock
    private TenantRepository tenantRepository;
    @Mock
    private TenantService tenantService;
    @Mock
    private IdentityAdministrationService identityAdministrationService;
    @Mock
    private LocalCredentialAuthService localCredentialAuthService;
    @Mock
    private DemoInviteEmailService demoInviteEmailService;
    @Mock
    private AuditEventService auditEventService;
    @Mock
    private SbomUploadRepository sbomUploadRepository;

    @Test
    void approveMarksInviteSentWhenEmailDeliverySucceeds() {
        DemoRequest request = pendingRequest();
        Tenant tenant = provisionedTenant();
        AtomicReference<DemoInvite> latestInvite = new AtomicReference<>();

        when(demoRequestRepository.findById(request.getId())).thenReturn(Optional.of(request));
        when(tenantRepository.findBySlugIgnoreCase("example-co")).thenReturn(Optional.empty());
        when(tenantService.createTenant("Example Co", "example-co", DemoLifecycleService.DEMO_PLAN_CODE, "demo-request:" + request.getId()))
                .thenReturn(tenant);
        when(tenantRepository.save(any(Tenant.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(demoInviteRepository.save(any(DemoInvite.class))).thenAnswer(invocation -> {
            DemoInvite invite = invocation.getArgument(0);
            if (invite.getId() == null) {
                ReflectionTestUtils.setField(invite, "id", UUID.randomUUID());
            }
            latestInvite.set(invite);
            return invite;
        });
        when(demoRequestRepository.save(any(DemoRequest.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(demoInviteRepository.findByRequest_IdOrderByCreatedAtDesc(request.getId()))
                .thenAnswer(invocation -> latestInvite.get() == null ? List.of() : List.of(latestInvite.get()));
        when(demoInviteEmailService.sendInvite(eq(request), any(DemoInvite.class)))
                .thenReturn(ResendEmailClient.DeliveryResult.sent("email-123"));

        DemoLifecycleService service = service();
        DemoRequestResponse response = service.approve(request.getId(), "platform-owner@example.com");

        assertEquals("PROVISIONED", response.status());
        assertNotNull(response.tenantId());
        assertEquals("SENT", response.latestInvite().status());
        assertNotNull(response.latestInvite().lastSentAt());
        verify(demoInviteEmailService).sendInvite(eq(request), any(DemoInvite.class));
    }

    @Test
    void approveLeavesInviteReadyWhenEmailDeliveryIsNotConfigured() {
        DemoRequest request = pendingRequest();
        Tenant tenant = provisionedTenant();
        AtomicReference<DemoInvite> latestInvite = new AtomicReference<>();

        when(demoRequestRepository.findById(request.getId())).thenReturn(Optional.of(request));
        when(tenantRepository.findBySlugIgnoreCase("example-co")).thenReturn(Optional.empty());
        when(tenantService.createTenant("Example Co", "example-co", DemoLifecycleService.DEMO_PLAN_CODE, "demo-request:" + request.getId()))
                .thenReturn(tenant);
        when(tenantRepository.save(any(Tenant.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(demoInviteRepository.save(any(DemoInvite.class))).thenAnswer(invocation -> {
            DemoInvite invite = invocation.getArgument(0);
            if (invite.getId() == null) {
                ReflectionTestUtils.setField(invite, "id", UUID.randomUUID());
            }
            latestInvite.set(invite);
            return invite;
        });
        when(demoRequestRepository.save(any(DemoRequest.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(demoInviteRepository.findByRequest_IdOrderByCreatedAtDesc(request.getId()))
                .thenAnswer(invocation -> latestInvite.get() == null ? List.of() : List.of(latestInvite.get()));
        when(demoInviteEmailService.sendInvite(eq(request), any(DemoInvite.class)))
                .thenReturn(ResendEmailClient.DeliveryResult.skipped("Resend delivery is not configured"));

        DemoLifecycleService service = service();
        DemoRequestResponse response = service.approve(request.getId(), "platform-owner@example.com");

        assertEquals("READY", response.latestInvite().status());
        assertNull(response.latestInvite().lastSentAt());
        verify(demoInviteEmailService).sendInvite(eq(request), any(DemoInvite.class));
    }

    @Test
    void resendInviteRetriesDeliveryForExistingInvite() {
        DemoRequest request = pendingRequest();
        request.setStatus("PROVISIONED");
        Tenant tenant = provisionedTenant();
        request.setTenantId(tenant.getId());

        DemoInvite existingInvite = new DemoInvite();
        ReflectionTestUtils.setField(existingInvite, "id", UUID.randomUUID());
        existingInvite.setRequest(request);
        existingInvite.setTenant(tenant);
        existingInvite.setEmail(request.getEmail());
        existingInvite.setToken("invite-token-123");
        existingInvite.setStatus("READY");
        existingInvite.setExpiresAt(java.time.Instant.now().plusSeconds(86400));

        when(demoRequestRepository.findById(request.getId())).thenReturn(Optional.of(request));
        when(demoInviteRepository.findByRequest_IdOrderByCreatedAtDesc(request.getId())).thenReturn(List.of(existingInvite));
        when(demoInviteRepository.save(any(DemoInvite.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(demoInviteEmailService.sendInvite(request, existingInvite))
                .thenReturn(ResendEmailClient.DeliveryResult.sent("email-456"));

        DemoLifecycleService service = service();
        DemoInviteResponse response = service.resendInvite(request.getId());

        assertEquals("SENT", response.status());
        assertNotNull(response.lastSentAt());
        verify(demoInviteEmailService).sendInvite(request, existingInvite);
    }

    private DemoLifecycleService service() {
        return new DemoLifecycleService(
                demoRequestRepository,
                demoInviteRepository,
                tenantRepository,
                tenantService,
                identityAdministrationService,
                localCredentialAuthService,
                demoInviteEmailService,
                auditEventService,
                sbomUploadRepository,
                "https://app.example.com"
        );
    }

    private DemoRequest pendingRequest() {
        DemoRequest request = new DemoRequest();
        ReflectionTestUtils.setField(request, "id", UUID.randomUUID());
        request.setEmail("alex@example.com");
        request.setFullName("Alex Rivera");
        request.setCompany("Example Co");
        request.setStatus("PENDING");
        return request;
    }

    private Tenant provisionedTenant() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Example Co");
        tenant.setSlug("example-co");
        return tenant;
    }

}
