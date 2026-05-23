package com.prototype.vulnwatch.service;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.doAnswer;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;

@ExtendWith(MockitoExtension.class)
class DemoTenantPurgeServiceTest {

    @Mock
    private TenantRepository tenantRepository;
    @Mock
    private JdbcTemplate resetJdbcTemplate;
    @Mock
    private JdbcTemplate tenantJdbcTemplate;
    @Mock
    private AuditEventService auditEventService;
    @Mock
    private TenantLifecycleGuardService tenantLifecycleGuardService;
    @Mock
    private TenantSchemaService tenantSchemaService;
    @Mock
    private TenantSchemaExecutionService tenantSchemaExecutionService;

    private DemoTenantPurgeService service;

    @BeforeEach
    void setUp() {
        service = new DemoTenantPurgeService(
                tenantRepository,
                resetJdbcTemplate,
                tenantJdbcTemplate,
                auditEventService,
                tenantLifecycleGuardService,
                tenantSchemaService,
                tenantSchemaExecutionService
        );
    }

    @Test
    void processExpiredTenantResetsTenantSchemaAndPurgesSharedRows() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Demo");
        tenant.setSlug("demo");
        tenant.setSchemaName("tenant_demo");
        tenant.setPlanCode("demo");
        tenant.setStatus("ACTIVE");
        tenant.setDemoExpiresAt(Instant.parse("2026-05-20T00:00:00Z"));

        Instant now = Instant.parse("2026-05-21T00:00:00Z");

        when(tenantRepository.findById(tenant.getId())).thenReturn(Optional.of(tenant));
        when(tenantLifecycleGuardService.isDemoTenant(tenant)).thenReturn(true);
        when(resetJdbcTemplate.query(any(String.class), any(org.springframework.jdbc.core.RowMapper.class), eq(tenant.getId())))
                .thenReturn(java.util.List.of());
        doAnswer(invocation -> {
            ((Runnable) invocation.getArgument(1)).run();
            return null;
        }).when(tenantSchemaExecutionService).run(eq(tenant), any(Runnable.class));

        service.processExpiredTenant(tenant.getId(), now);

        verify(tenantSchemaService).resetTenantSchema("tenant_demo");
        verify(tenantJdbcTemplate).update(
                "update demo_invites set status = ?, expires_at = least(expires_at, ?::timestamptz) where tenant_id = ? and upper(status) <> 'ACCEPTED'",
                "TENANT_EXPIRED",
                now,
                tenant.getId());
        verify(resetJdbcTemplate).update("delete from platform.tenant_support_grants where tenant_id = ?", tenant.getId());
        verify(resetJdbcTemplate).update("delete from platform.tenant_memberships where tenant_id = ?", tenant.getId());
        verify(auditEventService).record("demo.tenant.purged", "tenant", tenant.getId().toString(), null);
    }

    @Test
    void processExpiredTenantSkipsSchemaResetForNonDemoTenant() {
        UUID tenantId = UUID.randomUUID();
        Tenant tenant = new Tenant();
        tenant.setId(tenantId);

        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(tenantLifecycleGuardService.isDemoTenant(tenant)).thenReturn(false);

        service.processExpiredTenant(tenantId, Instant.now());

        verify(tenantSchemaService, never()).resetTenantSchema(any(String.class));
    }
}
