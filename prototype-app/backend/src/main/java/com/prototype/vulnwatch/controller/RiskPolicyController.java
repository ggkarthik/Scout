package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.RiskPolicyRequest;
import com.prototype.vulnwatch.dto.RiskPolicyResponse;
import com.prototype.vulnwatch.security.SensitiveTenantAction;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.FindingsScoreRecomputeService;
import com.prototype.vulnwatch.service.RiskPolicyService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.util.Map;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/risk-policy")
public class RiskPolicyController {

    private final WorkspaceService workspaceService;
    private final RiskPolicyService riskPolicyService;
    private final AuditEventService auditEventService;
    private final FindingsScoreRecomputeService findingsScoreRecomputeService;

    public RiskPolicyController(
            WorkspaceService workspaceService,
            RiskPolicyService riskPolicyService,
            AuditEventService auditEventService,
            FindingsScoreRecomputeService findingsScoreRecomputeService
    ) {
        this.workspaceService = workspaceService;
        this.riskPolicyService = riskPolicyService;
        this.auditEventService = auditEventService;
        this.findingsScoreRecomputeService = findingsScoreRecomputeService;
    }

    @GetMapping
    public RiskPolicyResponse get() {
        Tenant tenant = workspaceService.getWorkspace();
        return riskPolicyService.get(tenant);
    }

    @PostMapping
    @PreAuthorize("hasRole('TENANT_ADMIN')")
    @SensitiveTenantAction("risk_policy.updated")
    public RiskPolicyResponse update(@RequestBody RiskPolicyRequest request) {
        Tenant tenant = workspaceService.getWorkspace();
        RiskPolicyResponse response = riskPolicyService.update(tenant, request);
        auditEventService.record("risk_policy.updated", "risk_policy", tenant.getId().toString(), null);
        return response;
    }

    @PostMapping("/recompute-findings-scores")
    @PreAuthorize("hasRole('TENANT_ADMIN')")
    @SensitiveTenantAction("risk_policy.findings_score_recomputed")
    public Map<String, Object> recomputeFindingsScores() {
        Tenant tenant = workspaceService.getWorkspace();
        int updated = findingsScoreRecomputeService.recomputeAll(tenant);
        auditEventService.record("risk_policy.findings_score_recomputed", "risk_policy", tenant.getId().toString(), null);
        return Map.of("updated", updated);
    }
}
