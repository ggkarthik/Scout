package com.prototype.vulnwatch.service;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.server.ResponseStatusException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
class DemoTenantPurgeServiceTest {

    @Mock
    private TenantRepository tenantRepository;
    @Mock
    private AppUserRepository appUserRepository;
    @Mock
    private JdbcTemplate resetJdbcTemplate;
    @Mock
    private AuditEventService auditEventService;
    @Mock
    private TenantLifecycleGuardService tenantLifecycleGuardService;
    @Mock
    private TenantSchemaService tenantSchemaService;
    @Mock
    private DemoTenantPurgePlanner demoTenantPurgePlanner;

    private DemoTenantPurgeService service;

    @BeforeEach
    void setUp() {
        service = new DemoTenantPurgeService(
                tenantRepository,
                appUserRepository,
                resetJdbcTemplate,
                auditEventService,
                tenantLifecycleGuardService,
                tenantSchemaService,
                demoTenantPurgePlanner
        );
    }

    @Test
    void processExpiredTenantDropsTenantSchemaAndPurgesSharedRows() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Demo");
        tenant.setSlug("demo");
        tenant.setSchemaName("tenant_demo");
        tenant.setPlanCode("demo");
        tenant.setStatus("ACTIVE");
        tenant.setDemoExpiresAt(Instant.parse("2026-05-20T00:00:00Z"));

        Instant now = Instant.parse("2026-05-21T00:00:00Z");
        UUID userId = UUID.randomUUID();
        AppUser user = new AppUser();
        user.setId(userId);
        user.setStatus("ACTIVE");

        when(tenantRepository.findById(tenant.getId())).thenReturn(Optional.of(tenant));
        when(demoTenantPurgePlanner.isEligibleForAutomaticPurge(tenant, now)).thenReturn(true);
        when(resetJdbcTemplate.query(any(String.class), any(org.springframework.jdbc.core.RowMapper.class), eq(tenant.getId())))
                .thenReturn(java.util.List.of(userId));
        when(resetJdbcTemplate.queryForObject("select count(*) from platform.tenant_memberships where user_id = ?", Integer.class, userId))
                .thenReturn(0);
        when(appUserRepository.findById(userId)).thenReturn(Optional.of(user));
        when(resetJdbcTemplate.queryForList(any(String.class), eq(String.class)))
                .thenReturn(java.util.List.of("platform.tenant_support_grants", "platform.tenant_memberships"));

        service.processExpiredTenant(tenant.getId(), now);

        verify(tenantSchemaService).dropTenantSchema("tenant_demo");
        verify(resetJdbcTemplate).update("delete from platform.tenant_support_grants where tenant_id = ?", tenant.getId());
        verify(resetJdbcTemplate).update("delete from platform.tenant_memberships where tenant_id = ?", tenant.getId());
        verify(resetJdbcTemplate).update("update tenant_default.demo_requests set tenant_id = null where tenant_id = ?", tenant.getId());
        verify(resetJdbcTemplate).update("delete from platform.tenants where id = ?", tenant.getId());
        verify(appUserRepository).save(user);
        verify(auditEventService).record("demo.tenant.purged", "tenant", tenant.getId().toString(), null);
    }

    @Test
    void processExpiredTenantSkipsSchemaDropForNonDemoTenant() {
        UUID tenantId = UUID.randomUUID();
        Tenant tenant = new Tenant();
        tenant.setId(tenantId);

        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(demoTenantPurgePlanner.isEligibleForAutomaticPurge(eq(tenant), any())).thenReturn(false);

        service.processExpiredTenant(tenantId, Instant.now());

        verify(tenantSchemaService, never()).dropTenantSchema(any(String.class));
    }

    @Test
    void deleteTenantPurgesNonDemoTenantSchemaAndSharedRows() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Customer One");
        tenant.setSlug("customer-one");
        tenant.setSchemaName("tenant_customer_one");
        tenant.setPlanCode("pilot");
        tenant.setStatus("ACTIVE");

        Instant now = Instant.parse("2026-06-11T00:00:00Z");
        UUID userId = UUID.randomUUID();
        AppUser user = new AppUser();
        user.setId(userId);
        user.setStatus("ACTIVE");

        when(tenantRepository.findById(tenant.getId())).thenReturn(Optional.of(tenant));
        when(resetJdbcTemplate.query(any(String.class), any(org.springframework.jdbc.core.RowMapper.class), eq(tenant.getId())))
                .thenReturn(java.util.List.of(userId));
        when(resetJdbcTemplate.queryForObject("select count(*) from platform.tenant_memberships where user_id = ?", Integer.class, userId))
                .thenReturn(0);
        when(appUserRepository.findById(userId)).thenReturn(Optional.of(user));
        when(resetJdbcTemplate.queryForList(any(String.class), eq(String.class)))
                .thenReturn(java.util.List.of("platform.tenant_support_grants", "platform.tenant_memberships"));

        service.deleteTenant(tenant.getId(), now);

        verify(tenantSchemaService).dropTenantSchema("tenant_customer_one");
        verify(resetJdbcTemplate).update("delete from platform.tenant_support_grants where tenant_id = ?", tenant.getId());
        verify(resetJdbcTemplate).update("delete from platform.tenant_memberships where tenant_id = ?", tenant.getId());
        verify(resetJdbcTemplate).update("update tenant_default.demo_requests set tenant_id = null where tenant_id = ?", tenant.getId());
        verify(resetJdbcTemplate).update("delete from platform.tenants where id = ?", tenant.getId());
        verify(appUserRepository).save(user);
        verify(auditEventService).record("tenant.deleted", "tenant", tenant.getId().toString(), null);
    }

    @Test
    void deleteTenantRejectsDefaultWorkspace() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName(TenantService.DEFAULT_TENANT_NAME);

        when(tenantRepository.findById(tenant.getId())).thenReturn(Optional.of(tenant));

        ResponseStatusException ex = assertThrows(
                ResponseStatusException.class,
                () -> service.deleteTenant(tenant.getId(), Instant.now())
        );

        assertEquals(400, ex.getStatusCode().value());
        verify(tenantSchemaService, never()).dropTenantSchema(any(String.class));
    }

}
