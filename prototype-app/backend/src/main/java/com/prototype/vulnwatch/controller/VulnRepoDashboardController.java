package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.OrgCveAutomationStatusResponse;
import com.prototype.vulnwatch.dto.OrgSpecificCveExposurePageResponse;
import com.prototype.vulnwatch.dto.OrgSpecificCveExposureRecomputeResponse;
import com.prototype.vulnwatch.dto.TenantExposureRefreshResponse;
import com.prototype.vulnwatch.dto.VulnRepoDashboardResponse;
import com.prototype.vulnwatch.dto.VulnRepoSoftwareAssetsResponse;
import java.util.UUID;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.OrgCveAutomationStatusService;
import com.prototype.vulnwatch.service.TenantQuotaService;
import com.prototype.vulnwatch.service.VulnRepoDashboardService;
import com.prototype.vulnwatch.service.VulnRepoVulnerabilityQueryService;
import com.prototype.vulnwatch.service.VulnerabilityIntelMaintenanceService;
import com.prototype.vulnwatch.service.VulnerabilityIntelQueryService;
import com.prototype.vulnwatch.service.WorkspaceService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/vuln-repo")
public class VulnRepoDashboardController {

    private final WorkspaceService workspaceService;
    private final VulnRepoDashboardService vulnRepoDashboardService;
    private final VulnRepoVulnerabilityQueryService vulnRepoVulnerabilityQueryService;
    private final VulnerabilityIntelQueryService vulnerabilityIntelQueryService;
    private final VulnerabilityIntelMaintenanceService vulnerabilityIntelMaintenanceService;
    private final OrgCveAutomationStatusService orgCveAutomationStatusService;
    private final AuditEventService auditEventService;
    private final TenantQuotaService tenantQuotaService;

    public VulnRepoDashboardController(
            WorkspaceService workspaceService,
            VulnRepoDashboardService vulnRepoDashboardService,
            VulnRepoVulnerabilityQueryService vulnRepoVulnerabilityQueryService,
            VulnerabilityIntelQueryService vulnerabilityIntelQueryService,
            VulnerabilityIntelMaintenanceService vulnerabilityIntelMaintenanceService,
            OrgCveAutomationStatusService orgCveAutomationStatusService,
            AuditEventService auditEventService,
            TenantQuotaService tenantQuotaService
    ) {
        this.workspaceService = workspaceService;
        this.vulnRepoDashboardService = vulnRepoDashboardService;
        this.vulnRepoVulnerabilityQueryService = vulnRepoVulnerabilityQueryService;
        this.vulnerabilityIntelQueryService = vulnerabilityIntelQueryService;
        this.vulnerabilityIntelMaintenanceService = vulnerabilityIntelMaintenanceService;
        this.orgCveAutomationStatusService = orgCveAutomationStatusService;
        this.auditEventService = auditEventService;
        this.tenantQuotaService = tenantQuotaService;
    }

    @GetMapping("/dashboard")
    public VulnRepoDashboardResponse getDashboard() {
        return vulnRepoDashboardService.get(workspaceService.getWorkspace());
    }

    @GetMapping("/vulnerabilities")
    public OrgSpecificCveExposurePageResponse listVulnerabilities(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "25") int size,
            @RequestParam(required = false) String query,
            @RequestParam(required = false) Boolean inKev,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) Boolean exploitOnly,
            @RequestParam(required = false) Integer createdSinceDays,
            @RequestParam(required = false) String software,
            @RequestParam(required = false) String softwareScope,
            @RequestParam(required = false) String softwareIdentityId,
            @RequestParam(required = false) Boolean includeAll,
            @RequestParam(required = false) Boolean impactedOnly
    ) {
        return vulnRepoVulnerabilityQueryService.listVulnerabilities(
                workspaceService.getWorkspace(),
                page,
                size,
                query,
                inKev,
                severity,
                exploitOnly,
                createdSinceDays,
                software,
                softwareScope,
                softwareIdentityId,
                includeAll,
                impactedOnly
        );
    }

    @GetMapping("/org-cves")
    public OrgSpecificCveExposurePageResponse listOrgSpecificCves(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "25") int size,
            @RequestParam(required = false) String query,
            @RequestParam(required = false) Boolean inKev,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) Boolean exploitOnly,
            @RequestParam(required = false) Integer createdSinceDays,
            @RequestParam(required = false) String software,
            @RequestParam(required = false) String softwareScope,
            @RequestParam(required = false) String softwareIdentityId,
            @RequestParam(required = false) Boolean includeAll
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        return vulnerabilityIntelQueryService.listOrgSpecificCveExposure(
                tenant,
                page,
                size,
                query,
                inKev,
                severity,
                exploitOnly,
                createdSinceDays,
                software,
                softwareScope,
                softwareIdentityId,
                Boolean.TRUE.equals(includeAll),
                false
        );
    }

    @GetMapping("/org-cves/status")
    public OrgCveAutomationStatusResponse getOrgSpecificCveAutomationStatus() {
        return orgCveAutomationStatusService.getStatus(workspaceService.getWorkspace());
    }

    @PostMapping("/org-cves/recompute")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public OrgSpecificCveExposureRecomputeResponse recomputeOrgSpecificCves(
            @RequestParam(defaultValue = "targeted") String mode
    ) {
        boolean fullRecompute = "full".equalsIgnoreCase(mode);
        Tenant tenant = workspaceService.getWorkspace();
        OrgSpecificCveExposureRecomputeResponse response =
                vulnerabilityIntelMaintenanceService.recomputeOrgSpecificCveExposure(
                        tenant,
                        fullRecompute
                );
        auditEventService.record("platform.org_cves.recompute", "tenant", tenant.getId().toString(),
                "{\"mode\":\"" + mode + "\"}");
        return response;
    }

    @PostMapping("/org-cves/refresh")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public TenantExposureRefreshResponse refreshTenantExposure() {
        Tenant tenant = workspaceService.getWorkspace();
        tenantQuotaService.assertCanRefreshTenantExposure(tenant);
        TenantExposureRefreshResponse response =
                vulnerabilityIntelMaintenanceService.refreshTenantExposureFromCentralRepository(tenant);
        auditEventService.recordTenantExposureRefresh(tenant, "/api/vuln-repo/org-cves/refresh", response);
        return response;
    }

    @GetMapping("/software-assets/{softwareIdentityId}")
    public VulnRepoSoftwareAssetsResponse getSoftwareAssets(@PathVariable UUID softwareIdentityId) {
        return vulnRepoDashboardService.getSoftwareAssets(workspaceService.getWorkspace(), softwareIdentityId);
    }
}
