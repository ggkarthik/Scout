package com.prototype.vulnwatch.aisecurity.controller;

import com.prototype.vulnwatch.aisecurity.service.AiGridBudgetService;
import com.prototype.vulnwatch.aisecurity.service.AiGridBudgetService.BudgetConfig;
import com.prototype.vulnwatch.aisecurity.service.AiGridBudgetService.BudgetConfigCommand;
import com.prototype.vulnwatch.aisecurity.service.AiGridBudgetService.BudgetStatus;
import com.prototype.vulnwatch.aisecurity.service.AiGridBudgetService.CadenceCommand;
import com.prototype.vulnwatch.aisecurity.service.AiGridBudgetService.CadenceRule;
import com.prototype.vulnwatch.aisecurity.service.AiGridRetentionService;
import com.prototype.vulnwatch.aisecurity.service.AiGridRetentionService.EvidenceHold;
import com.prototype.vulnwatch.aisecurity.service.AiGridRetentionService.HoldCommand;
import com.prototype.vulnwatch.aisecurity.service.AiGridRetentionService.PolicyCommand;
import com.prototype.vulnwatch.aisecurity.service.AiGridRetentionService.RetentionPolicy;
import com.prototype.vulnwatch.aisecurity.service.AiGridRetentionService.RetentionStatus;
import com.prototype.vulnwatch.aisecurity.service.AiGridRetentionService.SweepResult;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAccessService;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.util.UUID;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/ai-governance")
public class AiGridOperationsGovernanceController {
    private final WorkspaceService workspaces;
    private final RequestActorService actors;
    private final AiSecurityAccessService access;
    private final AiGridBudgetService budgets;
    private final AiGridRetentionService retention;

    public AiGridOperationsGovernanceController(WorkspaceService workspaces, RequestActorService actors,
                                                AiSecurityAccessService access, AiGridBudgetService budgets,
                                                AiGridRetentionService retention) {
        this.workspaces = workspaces;
        this.actors = actors;
        this.access = access;
        this.budgets = budgets;
        this.retention = retention;
    }

    @GetMapping("/budget")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public BudgetStatus budget() { return budgets.status(tenant()); }

    @PutMapping("/budget")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN')")
    public BudgetConfig updateBudget(@RequestBody BudgetConfigCommand command) {
        return budgets.update(tenant(), command, actor());
    }

    @PutMapping("/cadence")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN')")
    public CadenceRule cadence(@RequestBody CadenceCommand command) {
        return budgets.upsertCadence(tenant(), command, actor());
    }

    @PostMapping("/budget-alerts/{alertId}/acknowledge")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public void acknowledge(@PathVariable UUID alertId) {
        budgets.acknowledgeAlert(tenant(), alertId, actor());
    }

    @GetMapping("/retention")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public RetentionStatus retention() { return retention.status(tenant()); }

    @PutMapping("/retention/policies")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN')")
    public RetentionPolicy updateRetention(@RequestBody PolicyCommand command) {
        return retention.updatePolicy(tenant(), command, actor());
    }

    @PostMapping("/retention/holds")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN')")
    public EvidenceHold hold(@RequestBody HoldCommand command) {
        return retention.createHold(tenant(), command, actor());
    }

    @PostMapping("/retention/holds/{holdId}/release")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN')")
    public EvidenceHold release(@PathVariable UUID holdId) {
        return retention.releaseHold(tenant(), holdId, actor());
    }

    @PostMapping("/retention/sweep")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN')")
    public SweepResult sweep() { return retention.sweep(tenant()); }

    private Tenant tenant() {
        Tenant tenant = workspaces.getWorkspace();
        access.assertEntitled(tenant);
        return tenant;
    }
    private String actor() { return actors.currentActor().userId(); }
}
