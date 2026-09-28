package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Daily admission budget for AI-BOM projection, checked at projection time (not enqueue time)
 * so a job that sat queued across a UTC day boundary is assessed against the day it actually
 * runs. Deliberately separate from {@code AiGridBudgetService} (the connector scan budget,
 * keyed by run_id with cadence rules for recurring scheduled scans) -- a different provider
 * label alone would not isolate this budget from that one, and there's no cadence concept for
 * an upload-triggered job anyway.
 */
@Service
public class AiBomProjectionBudgetService {

    public enum Decision { ADMITTED, THROTTLED }

    private final NamedParameterJdbcTemplate jdbc;
    private final TenantSchemaExecutionService tenantExecution;
    private final TransactionTemplate transactions;
    private final int dailyAdmissionLimit;

    public AiBomProjectionBudgetService(
            NamedParameterJdbcTemplate jdbc,
            TenantSchemaExecutionService tenantExecution,
            TransactionTemplate transactions,
            @Value("${app.ai-bom.projection.daily-admission-limit:100}") int dailyAdmissionLimit) {
        this.jdbc = jdbc;
        this.tenantExecution = tenantExecution;
        this.transactions = transactions;
        this.dailyAdmissionLimit = dailyAdmissionLimit;
    }

    public Decision admit(Tenant tenant) {
        return tenantExecution.run(tenant, () -> transactions.execute(status -> {
            LocalDate today = LocalDate.now(ZoneOffset.UTC);
            // Serialize the admission decision for this tenant/day so the daily cap is atomic
            // under concurrent projection workers -- same pattern as AiGridBudgetService.admit.
            jdbc.queryForObject("select pg_advisory_xact_lock(hashtextextended(:key, 0))::text",
                    Map.of("key", tenant.getId() + "|" + today), String.class);

            jdbc.update("""
                    insert into ai_bom_projection_admissions (tenant_id, admission_date)
                    values (:tenantId, :date)
                    on conflict (tenant_id, admission_date) do nothing
                    """, Map.of("tenantId", tenant.getId(), "date", java.sql.Date.valueOf(today)));

            Integer admittedCount = jdbc.queryForObject("""
                    select admitted_count from ai_bom_projection_admissions
                     where tenant_id = :tenantId and admission_date = :date
                    """, Map.of("tenantId", tenant.getId(), "date", java.sql.Date.valueOf(today)), Integer.class);

            boolean admitted = admittedCount != null && admittedCount < dailyAdmissionLimit;
            String column = admitted ? "admitted_count" : "throttled_count";
            jdbc.update("""
                    update ai_bom_projection_admissions
                       set %s = %s + 1, updated_at = now()
                     where tenant_id = :tenantId and admission_date = :date
                    """.formatted(column, column),
                    new MapSqlParameterSource().addValue("tenantId", tenant.getId())
                            .addValue("date", java.sql.Date.valueOf(today)));

            return admitted ? Decision.ADMITTED : Decision.THROTTLED;
        }));
    }
}
