package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.AuditEvent;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.OrgSpecificCveExposureRecomputeResponse;
import com.prototype.vulnwatch.dto.TenantExposureRefreshResponse;
import com.prototype.vulnwatch.repo.AuditEventRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class AuditEventServiceTest {

    @Mock
    AuditEventRepository auditEventRepository;
    @Mock
    TenantRepository tenantRepository;
    @Mock
    RequestActorService requestActorService;

    @Test
    void recordTenantExposureRefreshPersistsOperationalDetails() {
        UUID tenantId = UUID.fromString("00000000-0000-0000-0000-000000000001");
        Tenant tenant = new Tenant();
        tenant.setId(tenantId);
        when(requestActorService.currentActor()).thenReturn(new RequestActor(
                "analyst@example.com",
                false,
                tenantId,
                "Acme",
                Set.of("TENANT_ADMIN")));
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));

        AuditEventService service = new AuditEventService(auditEventRepository, tenantRepository, requestActorService);
        OrgSpecificCveExposureRecomputeResponse refresh = new OrgSpecificCveExposureRecomputeResponse(
                "targeted",
                4L,
                3,
                2,
                8L,
                1L,
                Instant.parse("2026-04-10T12:00:00Z"));
        TenantExposureRefreshResponse response = new TenantExposureRefreshResponse(
                tenantId,
                "completed",
                "Tenant exposure refreshed from the current central vulnerability repository.",
                refresh,
                Instant.parse("2026-04-10T12:00:01Z"));

        service.recordTenantExposureRefresh(tenant, "/api/vuln-repo/org-cves/refresh", response);

        ArgumentCaptor<AuditEvent> eventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditEventRepository).save(eventCaptor.capture());
        AuditEvent event = eventCaptor.getValue();
        assertEquals("tenant.org_cves.refresh", event.getAction());
        assertEquals("tenant", event.getTargetType());
        assertEquals(tenantId.toString(), event.getTargetId());
        assertEquals("analyst@example.com", event.getActorSubject());
        assertEquals("TENANT_ADMIN", event.getActorRole());
        assertTrue(event.getDetailsJson().contains("\"source\":\"central_vulnerability_repository\""));
        assertTrue(event.getDetailsJson().contains("\"endpoint\":\"/api/vuln-repo/org-cves/refresh\""));
        assertTrue(event.getDetailsJson().contains("\"activeComponentCount\":4"));
        assertTrue(event.getDetailsJson().contains("\"stateRowsChanged\":2"));
        assertTrue(event.getDetailsJson().contains("\"openFindingsCount\":1"));
    }
}
