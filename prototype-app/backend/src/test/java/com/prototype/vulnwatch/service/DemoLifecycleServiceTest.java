package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.DemoRequest;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantMembership;
import com.prototype.vulnwatch.repo.DemoInviteRepository;
import com.prototype.vulnwatch.repo.DemoRequestRepository;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class DemoLifecycleServiceTest {

    @Mock
    DemoRequestRepository demoRequestRepository;

    @Mock
    DemoInviteRepository demoInviteRepository;

    @Mock
    TenantRepository tenantRepository;

    @Mock
    TenantService tenantService;

    @Mock
    IdentityAdministrationService identityAdministrationService;

    @Mock
    AuditEventService auditEventService;

    @Mock
    SbomUploadRepository sbomUploadRepository;

    @Mock
    ValidationAuthService validationAuthService;

    @Mock
    ResendEmailService resendEmailService;

    @Test
    void approveFailsWhenEmailDeliveryFails() {
        UUID requestId = UUID.randomUUID();
        DemoRequest request = demoRequest(requestId);
        Tenant tenant = tenant(UUID.randomUUID(), "Example Co", "example-co");

        when(demoRequestRepository.findById(requestId)).thenReturn(Optional.of(request));
        when(tenantRepository.findBySlugIgnoreCase("example-co")).thenReturn(Optional.empty());
        when(tenantService.createTenant(eq("Example Co"), eq("example-co"), eq("DEMO"), eq("demo-request:" + requestId)))
                .thenReturn(tenant);
        when(tenantRepository.save(tenant)).thenReturn(tenant);
        TenantMembership membership = new TenantMembership();
        membership.setTenant(tenant);
        when(identityAdministrationService.addMember(
                eq(tenant.getId()),
                eq("alex@example.com"),
                eq("alex@example.com"),
                eq("Alex Rivera"),
                eq("TENANT_ADMIN"))).thenReturn(membership);
        when(demoInviteRepository.save(org.mockito.ArgumentMatchers.any())).thenAnswer(invocation -> invocation.getArgument(0));
        org.mockito.Mockito.doThrow(new IllegalStateException("Resend email delivery is disabled. Set APP_EMAIL_ENABLED=true to send demo invites."))
                .when(resendEmailService)
                .sendDemoInvite(org.mockito.ArgumentMatchers.any());

        DemoLifecycleService service = new DemoLifecycleService(
                demoRequestRepository,
                demoInviteRepository,
                tenantRepository,
                tenantService,
                identityAdministrationService,
                auditEventService,
                sbomUploadRepository,
                validationAuthService,
                resendEmailService,
                "https://app.example.com",
                24);

        IllegalStateException error = assertThrows(IllegalStateException.class, () -> service.approve(requestId, "owner@example.com"));
        assertEquals("Resend email delivery is disabled. Set APP_EMAIL_ENABLED=true to send demo invites.", error.getMessage());
    }

    private DemoRequest demoRequest(UUID id) {
        DemoRequest request = new DemoRequest();
        ReflectionTestUtils.setField(request, "id", id);
        request.setEmail("alex@example.com");
        request.setFullName("Alex Rivera");
        request.setCompany("Example Co");
        return request;
    }

    private Tenant tenant(UUID id, String name, String slug) {
        Tenant tenant = new Tenant();
        tenant.setId(id);
        tenant.setName(name);
        tenant.setSlug(slug);
        return tenant;
    }
}
