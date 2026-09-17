package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantService;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/** Deletes metadata-only runtime records after the configured retention period, tenant by tenant. */
@Service
public class AiAgentExecutionRetentionService {
    private final TenantService tenants; private final TenantSchemaExecutionService tenantExecution;
    private final NamedParameterJdbcTemplate jdbc; private final int retentionDays;
    public AiAgentExecutionRetentionService(TenantService tenants, TenantSchemaExecutionService tenantExecution,
                                            NamedParameterJdbcTemplate jdbc,
                                            @Value("${app.ai-security.runtime.retention-days:90}") int retentionDays) {
        this.tenants = tenants; this.tenantExecution = tenantExecution; this.jdbc = jdbc; this.retentionDays = Math.max(1, retentionDays);
    }
    @Scheduled(cron = "${app.ai-security.runtime.retention-cron:0 17 2 * * *}")
    public void purgeExpired() {
        TenantContext.runAsPlatform(() -> tenants.listActiveTenants().forEach(this::purge));
    }
    public int purge(Tenant tenant) {
        Instant cutoff = Instant.now().minus(retentionDays, ChronoUnit.DAYS);
        return tenantExecution.run(tenant, () -> jdbc.update("delete from ai_agent_executions where evidence_time < :cutoff",
                new org.springframework.jdbc.core.namedparam.MapSqlParameterSource("cutoff", java.sql.Timestamp.from(cutoff))));
    }
}
