package com.prototype.vulnwatch.controller;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.OrgCveAutomationStatusResponse;
import com.prototype.vulnwatch.dto.OrgSpecificCveExposurePageResponse;
import com.prototype.vulnwatch.dto.OrgSpecificCveExposureRecomputeResponse;
import com.prototype.vulnwatch.dto.OrgSpecificCveExposureRecordResponse;
import com.prototype.vulnwatch.dto.OrgSpecificCveExposureSummaryResponse;
import com.prototype.vulnwatch.dto.TenantExposureRefreshResponse;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.OrgCveAutomationStatusService;
import com.prototype.vulnwatch.service.TenantQuotaService;
import com.prototype.vulnwatch.service.VulnRepoDashboardService;
import com.prototype.vulnwatch.service.VulnRepoVulnerabilityQueryService;
import com.prototype.vulnwatch.service.VulnerabilityIntelMaintenanceService;
import com.prototype.vulnwatch.service.VulnerabilityIntelQueryService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@ExtendWith(MockitoExtension.class)
class VulnRepoDashboardControllerTest {

    @Mock
    private WorkspaceService workspaceService;

    @Mock
    private VulnRepoDashboardService vulnRepoDashboardService;

    @Mock
    private VulnRepoVulnerabilityQueryService vulnRepoVulnerabilityQueryService;
    @Mock
    private VulnerabilityIntelQueryService vulnerabilityIntelQueryService;
    @Mock
    private VulnerabilityIntelMaintenanceService vulnerabilityIntelMaintenanceService;
    @Mock
    private OrgCveAutomationStatusService orgCveAutomationStatusService;
    @Mock
    private AuditEventService auditEventService;
    @Mock
    private TenantQuotaService tenantQuotaService;

    private MockMvc mockMvc;
    private Tenant tenant;

    @BeforeEach
    void setUp() {
        VulnRepoDashboardController controller = new VulnRepoDashboardController(
                workspaceService,
                vulnRepoDashboardService,
                vulnRepoVulnerabilityQueryService,
                vulnerabilityIntelQueryService,
                vulnerabilityIntelMaintenanceService,
                orgCveAutomationStatusService,
                auditEventService,
                tenantQuotaService
        );
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();

        tenant = new Tenant();
        tenant.setId(UUID.fromString("00000000-0000-0000-0000-000000000001"));
        tenant.setName("default");
    }

    @Test
    void vulnerabilitiesEndpointReturnsPageMetadataAndRows() throws Exception {
        when(workspaceService.getWorkspace()).thenReturn(tenant);
        when(vulnRepoVulnerabilityQueryService.listVulnerabilities(
                tenant,
                1,
                25,
                "CVE-2026-23360",
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null
        , null)).thenReturn(new OrgSpecificCveExposurePageResponse(
                new OrgSpecificCveExposureSummaryResponse(7L, 5L, 3L, 1L, 2L),
                List.of(new OrgSpecificCveExposureRecordResponse(
                        UUID.fromString("10000000-0000-0000-0000-000000000001"),
                        UUID.fromString("20000000-0000-0000-0000-000000000001"),
                        "CVE-2026-23360",
                        "Canonical only",
                        "Only ingested",
                        "UNKNOWN",
                        false,
                        "UNKNOWN",
                        null,
                        null,
                        "HIGH",
                        8.8,
                        0.12,
                        false,
                        0L,
                        0L,
                        0L,
                        0L,
                        0L,
                        0L,
                        0L,
                        0L,
                        0L,
                        0L,
                        0L,
                        null,
                        0L,
                        0L,
                        false,
                        null,
                        null,
                        false,
                        null,
                        null,
                        null,
                        null,
                        java.util.List.of()
                )),
                1,
                25,
                41L,
                2
        ));

        mockMvc.perform(get("/api/vuln-repo/vulnerabilities")
                        .param("page", "1")
                        .param("size", "25")
                        .param("query", "CVE-2026-23360"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.page").value(1))
                .andExpect(jsonPath("$.size").value(25))
                .andExpect(jsonPath("$.totalItems").value(41))
                .andExpect(jsonPath("$.totalPages").value(2))
                .andExpect(jsonPath("$.items[0].externalId").value("CVE-2026-23360"))
                .andExpect(jsonPath("$.items[0].impactState").value("UNKNOWN"));

        verify(vulnRepoVulnerabilityQueryService).listVulnerabilities(
                tenant,
                1,
                25,
                "CVE-2026-23360",
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null
        , null);
    }

    @Test
    void orgCvesAliasDelegatesToExistingProjectionQuery() throws Exception {
        when(workspaceService.getWorkspace()).thenReturn(tenant);
        when(vulnerabilityIntelQueryService.listOrgSpecificCveExposure(
                tenant,
                0,
                25,
                "CVE-2026-2001",
                true,
                "CRITICAL",
                true,
                30,
                "openssl",
                "broad",
                "00000000-0000-0000-0000-000000000099",
                true,
                false
        , null)).thenReturn(new OrgSpecificCveExposurePageResponse(
                new OrgSpecificCveExposureSummaryResponse(1L, 1L, 1L, 0L, 0L),
                List.of(),
                0,
                25,
                1L,
                1
        ));

        mockMvc.perform(get("/api/vuln-repo/org-cves")
                        .param("query", "CVE-2026-2001")
                        .param("inKev", "true")
                        .param("severity", "CRITICAL")
                        .param("exploitOnly", "true")
                        .param("createdSinceDays", "30")
                        .param("software", "openssl")
                        .param("softwareScope", "broad")
                        .param("softwareIdentityId", "00000000-0000-0000-0000-000000000099")
                        .param("includeAll", "true"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalItems").value(1));

        verify(vulnerabilityIntelQueryService).listOrgSpecificCveExposure(
                tenant,
                0,
                25,
                "CVE-2026-2001",
                true,
                "CRITICAL",
                true,
                30,
                "openssl",
                "broad",
                "00000000-0000-0000-0000-000000000099",
                true,
                false
        , null);
    }

    @Test
    void orgCveStatusAliasDelegatesToExistingStatusService() throws Exception {
        when(workspaceService.getWorkspace()).thenReturn(tenant);
        when(orgCveAutomationStatusService.getStatus(tenant)).thenReturn(new OrgCveAutomationStatusResponse(
                true,
                4L,
                Map.of("CVE_DELTA", 4L),
                1L,
                0L,
                Instant.parse("2026-04-10T10:15:30Z"),
                Instant.parse("2026-04-10T10:00:00Z"),
                Instant.parse("2026-04-09T08:00:00Z")
        ));

        mockMvc.perform(get("/api/vuln-repo/org-cves/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.automationEnabled").value(true))
                .andExpect(jsonPath("$.pendingEventCount").value(4))
                .andExpect(jsonPath("$.pendingByType.CVE_DELTA").value(4));

        verify(orgCveAutomationStatusService).getStatus(tenant);
    }

    @Test
    void orgCveRecomputeAliasDelegatesToExistingMaintenanceService() throws Exception {
        when(workspaceService.getWorkspace()).thenReturn(tenant);
        when(vulnerabilityIntelMaintenanceService.recomputeOrgSpecificCveExposure(tenant, true))
                .thenReturn(new OrgSpecificCveExposureRecomputeResponse(
                        "full",
                        12L,
                        9,
                        5,
                        18L,
                        3L,
                        Instant.parse("2026-04-10T12:00:00Z")
                ));

        mockMvc.perform(post("/api/vuln-repo/org-cves/recompute")
                        .param("mode", "full"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.scope").value("full"))
                .andExpect(jsonPath("$.stateRowsChanged").value(5));

        verify(vulnerabilityIntelMaintenanceService).recomputeOrgSpecificCveExposure(tenant, true);
    }

    @Test
    void tenantRefreshAliasDelegatesToMaintenanceService() throws Exception {
        when(workspaceService.getWorkspace()).thenReturn(tenant);
        OrgSpecificCveExposureRecomputeResponse refresh = new OrgSpecificCveExposureRecomputeResponse(
                "targeted",
                4L,
                3,
                2,
                8L,
                1L,
                Instant.parse("2026-04-10T12:00:00Z")
        );
        TenantExposureRefreshResponse response = new TenantExposureRefreshResponse(
                tenant.getId(),
                "completed",
                "Tenant exposure refreshed from the current central vulnerability repository.",
                refresh,
                Instant.parse("2026-04-10T12:00:01Z")
        );
        when(vulnerabilityIntelMaintenanceService.refreshTenantExposureFromCentralRepository(tenant))
                .thenReturn(response);

        mockMvc.perform(post("/api/vuln-repo/org-cves/refresh"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("completed"))
                .andExpect(jsonPath("$.tenantId").value(tenant.getId().toString()))
                .andExpect(jsonPath("$.refresh.scope").value("targeted"));

        verify(vulnerabilityIntelMaintenanceService).refreshTenantExposureFromCentralRepository(tenant);
        verify(tenantQuotaService).assertCanRefreshTenantExposure(tenant);
        verify(auditEventService).recordTenantExposureRefresh(tenant, "/api/vuln-repo/org-cves/refresh", response);
    }
}
