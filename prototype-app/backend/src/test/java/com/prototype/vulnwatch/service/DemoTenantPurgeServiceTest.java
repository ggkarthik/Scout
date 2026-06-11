package com.prototype.vulnwatch.service;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
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
    private JdbcTemplate resetJdbcTemplate;
    @Mock
    private AuditEventService auditEventService;
    @Mock
    private TenantLifecycleGuardService tenantLifecycleGuardService;
    @Mock
    private TenantSchemaService tenantSchemaService;

    private DemoTenantPurgeService service;

    @BeforeEach
    void setUp() {
        service = new DemoTenantPurgeService(
                tenantRepository,
                resetJdbcTemplate,
                auditEventService,
                tenantLifecycleGuardService,
                tenantSchemaService
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
        UUID userId = UUID.randomUUID();

        when(tenantRepository.findById(tenant.getId())).thenReturn(Optional.of(tenant));
        when(tenantLifecycleGuardService.isDemoTenant(tenant)).thenReturn(true);
        when(tenantSchemaService.schemaNameForTenant(tenant)).thenReturn("tenant_demo");
        when(resetJdbcTemplate.query(any(String.class), any(org.springframework.jdbc.core.RowMapper.class), eq(tenant.getId())))
                .thenReturn(java.util.List.of(userId));
        when(resetJdbcTemplate.queryForObject(any(String.class), eq(Integer.class), eq("tenant_demo"), eq("demo_invites")))
                .thenReturn(1);
        when(resetJdbcTemplate.queryForList(any(String.class), eq(String.class)))
                .thenReturn(java.util.List.of("platform.tenant_support_grants", "platform.tenant_memberships"));

        service.processExpiredTenant(tenant.getId(), now);

        verify(tenantSchemaService).resetTenantSchema("tenant_demo");
        verify(resetJdbcTemplate).update(
                """
                update "tenant_demo".demo_invites
                set status = ?, expires_at = least(expires_at, cast(? as timestamptz))
                where tenant_id = ? and upper(status) <> 'ACCEPTED'
                """,
                "TENANT_EXPIRED",
                now,
                tenant.getId());
        verify(resetJdbcTemplate).update("delete from platform.tenant_support_grants where tenant_id = ?", tenant.getId());
        verify(resetJdbcTemplate).update("delete from platform.tenant_memberships where tenant_id = ?", tenant.getId());
        verify(resetJdbcTemplate).update("update tenant_default.demo_requests set tenant_id = null where tenant_id = ?", tenant.getId());
        verify(resetJdbcTemplate).update("delete from platform.tenants where id = ?", tenant.getId());
        verify(resetJdbcTemplate).update("""
                    update platform.app_users u
                    set password_hash = null,
                        password_set_at = null,
                        password_setup_token_hash = null,
                        password_setup_token_expires_at = null,
                        status = case
                            when u.platform_owner = false
                                 and not exists (select 1 from platform.tenant_memberships tm where tm.user_id = u.id)
                            then 'INACTIVE'
                            else u.status
                        end,
                        updated_at = ?
                    where u.id = ?
                      and u.platform_owner = false
                    """, now, userId);
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

        when(tenantRepository.findById(tenant.getId())).thenReturn(Optional.of(tenant));
        when(tenantSchemaService.schemaNameForTenant(tenant)).thenReturn("tenant_customer_one");
        when(resetJdbcTemplate.query(any(String.class), any(org.springframework.jdbc.core.RowMapper.class), eq(tenant.getId())))
                .thenReturn(java.util.List.of(userId));
        when(resetJdbcTemplate.queryForObject(any(String.class), eq(Integer.class), eq("tenant_customer_one"), eq("demo_invites")))
                .thenReturn(1);
        when(resetJdbcTemplate.queryForList(any(String.class), eq(String.class)))
                .thenReturn(java.util.List.of("platform.tenant_support_grants", "platform.tenant_memberships"));

        service.deleteTenant(tenant.getId(), now);

        verify(tenantSchemaService).resetTenantSchema("tenant_customer_one");
        verify(resetJdbcTemplate).update(
                """
                update "tenant_customer_one".demo_invites
                set status = ?, expires_at = least(expires_at, cast(? as timestamptz))
                where tenant_id = ? and upper(status) <> 'ACCEPTED'
                """,
                "TENANT_EXPIRED",
                now,
                tenant.getId());
        verify(resetJdbcTemplate).update("delete from platform.tenant_support_grants where tenant_id = ?", tenant.getId());
        verify(resetJdbcTemplate).update("delete from platform.tenant_memberships where tenant_id = ?", tenant.getId());
        verify(resetJdbcTemplate).update("update tenant_default.demo_requests set tenant_id = null where tenant_id = ?", tenant.getId());
        verify(resetJdbcTemplate).update("delete from platform.tenants where id = ?", tenant.getId());
        verify(resetJdbcTemplate).update("""
                    update platform.app_users u
                    set password_hash = null,
                        password_set_at = null,
                        password_setup_token_hash = null,
                        password_setup_token_expires_at = null,
                        status = case
                            when u.platform_owner = false
                                 and not exists (select 1 from platform.tenant_memberships tm where tm.user_id = u.id)
                            then 'INACTIVE'
                            else u.status
                        end,
                        updated_at = ?
                    where u.id = ?
                      and u.platform_owner = false
                    """, now, userId);
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
        verify(tenantSchemaService, never()).resetTenantSchema(any(String.class));
    }

    @Test
    void deleteTenantSkipsInviteUpdateWhenTenantSchemaDoesNotContainDemoInvites() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Customer Two");
        tenant.setSchemaName("tenant_customer_two");
        tenant.setStatus("ACTIVE");

        Instant now = Instant.parse("2026-06-11T00:00:00Z");
        UUID userId = UUID.randomUUID();

        when(tenantRepository.findById(tenant.getId())).thenReturn(Optional.of(tenant));
        when(tenantSchemaService.schemaNameForTenant(tenant)).thenReturn("tenant_customer_two");
        when(resetJdbcTemplate.query(any(String.class), any(org.springframework.jdbc.core.RowMapper.class), eq(tenant.getId())))
                .thenReturn(java.util.List.of(userId));
        when(resetJdbcTemplate.queryForObject(any(String.class), eq(Integer.class), eq("tenant_customer_two"), eq("demo_invites")))
                .thenReturn(0);
        when(resetJdbcTemplate.queryForList(any(String.class), eq(String.class)))
                .thenReturn(java.util.List.of("platform.tenant_support_grants", "platform.tenant_memberships"));

        service.deleteTenant(tenant.getId(), now);

        verify(resetJdbcTemplate, never()).update(
                """
                update "tenant_customer_two".demo_invites
                set status = ?, expires_at = least(expires_at, cast(? as timestamptz))
                where tenant_id = ? and upper(status) <> 'ACCEPTED'
                """,
                "TENANT_EXPIRED",
                now,
                tenant.getId());
        verify(tenantSchemaService).resetTenantSchema("tenant_customer_two");
        verify(resetJdbcTemplate).update("delete from platform.tenants where id = ?", tenant.getId());
    }
}
