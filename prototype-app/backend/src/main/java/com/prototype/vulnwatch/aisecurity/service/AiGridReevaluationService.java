package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

/** Re-runs the canonical AI Grid assessment after a tenant policy edit. */
@Service
public class AiGridReevaluationService {
    private final NamedParameterJdbcTemplate jdbc;
    private final TenantSchemaExecutionService tenantExecution;
    private final AiGridApiService aiGrid;

    private org.springframework.beans.factory.ObjectProvider<AiGridAssessmentWorker> assessmentWorker;
    @org.springframework.beans.factory.annotation.Autowired
    void configureAssessmentWorker(org.springframework.beans.factory.ObjectProvider<AiGridAssessmentWorker> worker) {
        this.assessmentWorker = worker;
    }

    public AiGridReevaluationService(NamedParameterJdbcTemplate jdbc,
                                     TenantSchemaExecutionService tenantExecution,
                                     AiGridApiService aiGrid) {
        this.jdbc = jdbc;
        this.tenantExecution = tenantExecution;
        this.aiGrid = aiGrid;
    }

    public void preflight(Tenant tenant, String policyId, java.util.Map<String, Object> proposedParameters) {
        aiGrid.preflight(tenant, policyId, proposedParameters);
    }

    public void reevaluatePolicy(Tenant tenant, String policyId) {
        UUID latestRun = tenantExecution.run(tenant, () -> jdbc.query("""
                select run_id
                  from ai_grid_snapshot_manifests
                 order by observed_at desc, created_at desc
                 limit 1
                """, rs -> rs.next() ? rs.getObject("run_id", UUID.class) : null));
        if (latestRun != null) {
            assessmentWorker.getObject().enqueue(tenant, latestRun, java.util.Set.of(policyId));
        }
    }
}
