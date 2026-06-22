package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.InventoryConnectorHealthResponse;
import com.prototype.vulnwatch.dto.OperationalConnectorIssueGroupResponse;
import com.prototype.vulnwatch.dto.OperationalTenantAttentionResponse;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class PlatformTenantAttentionServiceTest {

    @Mock
    private TenantService tenantService;

    @Mock
    private PlatformInventoryConnectorHealthService platformInventoryConnectorHealthService;

    private PlatformTenantAttentionService service;

    @BeforeEach
    void setUp() {
        service = new PlatformTenantAttentionService(tenantService, platformInventoryConnectorHealthService);
    }

    @Test
    void buildsTenantAttentionQueueFromLifecycleAndConnectorSignals() {
        Tenant suspended = tenant("Suspended Co", "SUSPENDED");
        Tenant expired = tenant("Expired Co", "EXPIRED");
        Tenant active = tenant("Active Co", "ACTIVE");
        Tenant healthy = tenant("Healthy Co", "ACTIVE");
        when(tenantService.listTenants()).thenReturn(List.of(active, healthy, expired, suspended));
        when(platformInventoryConnectorHealthService.listInventoryConnectorHealth()).thenReturn(List.of(
                connector(active, "aws", "ERROR", Instant.parse("2026-06-20T10:00:00Z")),
                connector(active, "servicenow", "PENDING", null),
                connector(healthy, "sccm", "HEALTHY", Instant.parse("2026-06-20T09:00:00Z"))
        ));

        List<OperationalTenantAttentionResponse> rows = service.listTenantAttention();

        assertEquals(3, rows.size());
        assertEquals("Suspended Co", rows.get(0).tenantName());
        assertEquals(List.of("TENANT_SUSPENDED"), rows.get(0).reasons());
        assertNull(rows.get(0).latestRelevantSyncAt());

        assertEquals("Expired Co", rows.get(1).tenantName());
        assertEquals(List.of("TENANT_EXPIRED"), rows.get(1).reasons());

        assertEquals("Active Co", rows.get(2).tenantName());
        assertEquals(List.of("CONNECTOR_ERROR", "CONNECTOR_PENDING"), rows.get(2).reasons());
        assertEquals(List.of("aws", "servicenow"), rows.get(2).affectedConnectors());
        assertEquals(Instant.parse("2026-06-20T10:00:00Z"), rows.get(2).latestRelevantSyncAt());
    }

    @Test
    void excludesHealthyActiveTenantsFromAttentionQueue() {
        Tenant healthy = tenant("Healthy Co", "ACTIVE");
        when(tenantService.listTenants()).thenReturn(List.of(healthy));
        when(platformInventoryConnectorHealthService.listInventoryConnectorHealth()).thenReturn(List.of(
                connector(healthy, "aws", "HEALTHY", Instant.parse("2026-06-20T10:00:00Z"))
        ));

        List<OperationalTenantAttentionResponse> rows = service.listTenantAttention();

        assertEquals(0, rows.size());
    }

    @Test
    void groupsConnectorIssuesByConnectorKey() {
        Tenant alpha = tenant("Alpha", "ACTIVE");
        Tenant beta = tenant("Beta", "ACTIVE");
        when(platformInventoryConnectorHealthService.listInventoryConnectorHealth()).thenReturn(List.of(
                connector(alpha, "aws", "ERROR", Instant.parse("2026-06-20T10:00:00Z")),
                connector(beta, "aws", "PENDING", null),
                connector(alpha, "servicenow", "ERROR", Instant.parse("2026-06-20T09:00:00Z")),
                connector(beta, "sccm", "HEALTHY", Instant.parse("2026-06-20T09:00:00Z"))
        ));

        List<OperationalConnectorIssueGroupResponse> groups = service.listConnectorIssues();

        assertEquals(2, groups.size());
        assertEquals("aws", groups.get(0).connectorKey());
        assertEquals(2, groups.get(0).affectedTenantCount());
        assertEquals(List.of("Alpha", "Beta"), groups.get(0).affectedTenants());
        assertEquals("servicenow", groups.get(1).connectorKey());
        assertEquals(1, groups.get(1).affectedTenantCount());
    }

    private Tenant tenant(String name, String status) {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName(name);
        tenant.setStatus(status);
        tenant.setSlug(name.toLowerCase().replace(' ', '-'));
        tenant.setSchemaName("tenant_" + tenant.getSlug());
        return tenant;
    }

    private InventoryConnectorHealthResponse connector(Tenant tenant, String key, String healthState, Instant lastSyncAt) {
        return new InventoryConnectorHealthResponse(
                (UUID) tenant.getId(),
                tenant.getName(),
                key,
                true,
                true,
                "ERROR".equals(healthState) ? "FAILED" : "PASSED",
                null,
                null,
                lastSyncAt,
                healthState
        );
    }
}
