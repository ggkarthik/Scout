package com.prototype.vulnwatch.aisecurity.copilot;

import com.prototype.vulnwatch.aisecurity.service.AiGridBudgetService;
import com.prototype.vulnwatch.aisecurity.service.AiGridProviderCallCounter;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityDiscoveryProvider;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.IngestionJobService;
import java.util.UUID;
import org.springframework.stereotype.Component;

/** Bridges Copilot discovery into the same durable AI Security ingestion worker as AWS and Azure. */
@Component
public class CopilotStudioDiscoveryProvider implements AiSecurityDiscoveryProvider {
    private final CopilotStudioDiscoveryService discovery;

    public CopilotStudioDiscoveryProvider(CopilotStudioDiscoveryService discovery) {
        this.discovery = discovery;
    }

    @Override public String provider() { return "MICROSOFT_COPILOT"; }
    @Override public String jobType() { return IngestionJobService.JOB_TYPE_AI_SECURITY_COPILOT_STUDIO; }
    @Override public Object discover(Tenant tenant, UUID connectorId) { return discovery.run(tenant, connectorId); }

    @Override public String failureCode(Exception exception) {
        if (exception instanceof AiGridBudgetService.BudgetExceededException) return "BUDGET_THROTTLED";
        if (exception instanceof AiGridProviderCallCounter.ProviderCallBudgetExceededException) return "BUDGET_THROTTLED";
        return AiSecurityDiscoveryProvider.super.failureCode(exception);
    }

    @Override public String safeFailureMessage(String code) {
        return "BUDGET_THROTTLED".equals(code)
                ? "Copilot Studio discovery was deferred by the tenant budget policy"
                : AiSecurityDiscoveryProvider.super.safeFailureMessage(code);
    }
}
