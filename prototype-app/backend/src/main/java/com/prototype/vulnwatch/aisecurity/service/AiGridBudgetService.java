package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AiGridBudgetService {
    private final NamedParameterJdbcTemplate jdbc;
    private final TenantSchemaExecutionService tenantExecution;
    private final TransactionTemplate transactions;
    private final ObjectMapper objectMapper;

    public AiGridBudgetService(NamedParameterJdbcTemplate jdbc, TenantSchemaExecutionService tenantExecution,
                               TransactionTemplate transactions, ObjectMapper objectMapper) {
        this.jdbc = jdbc;
        this.tenantExecution = tenantExecution;
        this.transactions = transactions;
        this.objectMapper = objectMapper;
    }

    public Admission admit(Tenant tenant, UUID runId, String provider, List<String> resourceFamilies,
                           String environment, String criticality) {
        Admission admission = transactions.execute(status -> {
            BudgetConfig config = current();
            BudgetUsage usage = usage();
            List<String> blockers = exceeded(config, usage, true);
            cadenceBlocker(provider, resourceFamilies, environment, criticality).ifPresent(blockers::add);
            boolean throttled = "THROTTLE".equals(config.enforcementMode()) && !blockers.isEmpty();
            String decision = throttled ? "THROTTLED" : "ADMITTED";
            String reason = blockers.isEmpty() ? "WITHIN_BUDGET" : String.join(",", blockers);
            jdbc.update("""
                    insert into ai_grid_budget_admissions
                        (id, tenant_id, run_id, provider, resource_families_json, decision, reason_code, usage_json)
                    values (:id, :tenantId, :runId, :provider, cast(:families as jsonb),
                            :decision, :reason, cast(:usage as jsonb))
                    on conflict (tenant_id, run_id) do nothing
                    """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                    .addValue("runId", runId).addValue("provider", provider)
                    .addValue("families", json(resourceFamilies == null ? List.of() : resourceFamilies))
                    .addValue("decision", decision).addValue("reason", reason).addValue("usage", json(usage)));
            reconcileAlerts(runId, config, usage);
            return new Admission(runId, decision, reason, usage);
        });
        if (admission != null && "THROTTLED".equals(admission.decision())) {
            throw new BudgetExceededException(admission.reasonCode());
        }
        return admission;
    }

    public BudgetStatus status(Tenant tenant) {
        return tenantExecution.run(tenant, () -> new BudgetStatus(current(), usage(), alerts()));
    }

    public BudgetConfig update(Tenant tenant, BudgetConfigCommand command, String actor) {
        if (!List.of("OBSERVE", "THROTTLE").contains(command.enforcementMode())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid enforcement mode");
        }
        if (command.warningRatio() <= 0 || command.warningRatio() >= 1) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "warningRatio must be between zero and one");
        }
        return tenantExecution.run(tenant, () -> transactions.execute(status -> {
            jdbc.update("""
                    update ai_grid_budget_config set enforcement_mode = :mode,
                        daily_scan_limit = :scans, daily_provider_api_call_limit = :calls,
                        daily_new_snapshot_bytes_limit = :newBytes, daily_processing_ms_limit = :processing,
                        retained_snapshot_bytes_limit = :retained, warning_ratio = :warning,
                        updated_by = :actor, reason = :reason, updated_at = now()
                     where tenant_id = :tenantId
                    """, new MapSqlParameterSource().addValue("mode", command.enforcementMode())
                    .addValue("scans", positive(command.dailyScanLimit(), "dailyScanLimit"))
                    .addValue("calls", positive(command.dailyProviderApiCallLimit(), "dailyProviderApiCallLimit"))
                    .addValue("newBytes", positive(command.dailyNewSnapshotBytesLimit(), "dailyNewSnapshotBytesLimit"))
                    .addValue("processing", positive(command.dailyProcessingMsLimit(), "dailyProcessingMsLimit"))
                    .addValue("retained", positive(command.retainedSnapshotBytesLimit(), "retainedSnapshotBytesLimit"))
                    .addValue("warning", command.warningRatio()).addValue("actor", actor)
                    .addValue("reason", required(command.reason(), "reason")).addValue("tenantId", tenant.getId()));
            reconcileAlerts(null, current(), usage());
            return current();
        }));
    }

    public CadenceRule upsertCadence(Tenant tenant, CadenceCommand command, String actor) {
        if (command.minimumIntervalSeconds() < 0) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "minimumIntervalSeconds cannot be negative");
        }
        return tenantExecution.run(tenant, () -> transactions.execute(status -> {
            UUID id = UUID.randomUUID();
            jdbc.update("""
                    insert into ai_grid_scan_cadence_rules
                        (id, tenant_id, provider, resource_family, environment, criticality,
                         minimum_interval_seconds, enabled, updated_by, reason)
                    values (:id, :tenantId, :provider, :family, :environment, :criticality,
                            :seconds, :enabled, :actor, :reason)
                    on conflict (tenant_id, provider, resource_family, environment, criticality)
                    do update set minimum_interval_seconds = excluded.minimum_interval_seconds,
                        enabled = excluded.enabled, updated_by = excluded.updated_by,
                        reason = excluded.reason, updated_at = now()
                    """, new MapSqlParameterSource().addValue("id", id).addValue("tenantId", tenant.getId())
                    .addValue("provider", required(command.provider(), "provider"))
                    .addValue("family", wildcard(command.resourceFamily()))
                    .addValue("environment", wildcard(command.environment()))
                    .addValue("criticality", wildcard(command.criticality()))
                    .addValue("seconds", command.minimumIntervalSeconds()).addValue("enabled", command.enabled())
                    .addValue("actor", actor).addValue("reason", required(command.reason(), "reason")));
            return cadenceRules().stream().filter(rule -> rule.id().equals(id)).findFirst()
                    .orElseGet(() -> cadenceRules().stream()
                            .filter(rule -> rule.provider().equals(command.provider())
                                    && rule.resourceFamily().equals(wildcard(command.resourceFamily()))
                                    && rule.environment().equals(wildcard(command.environment()))
                                    && rule.criticality().equals(wildcard(command.criticality())))
                            .findFirst().orElseThrow());
        }));
    }

    public void reconcile(Tenant tenant, UUID runId, String provider) {
        transactions.executeWithoutResult(status -> {
            BudgetConfig config = current();
            BudgetUsage usage = usage();
            List<String> exceeded = exceeded(config, usage, true);
            jdbc.update("""
                    update ai_grid_run_metrics set provider = :provider,
                        retained_snapshot_bytes = :retained,
                        budget_state = :state, updated_at = now()
                     where run_id = :runId
                    """, Map.of("provider", provider, "retained", usage.retainedSnapshotBytes(),
                    "state", exceeded.isEmpty() ? "WITHIN_BUDGET" : "EXCEEDED", "runId", runId));
            reconcileAlerts(runId, config, usage);
        });
    }

    public void acknowledgeAlert(Tenant tenant, UUID alertId, String actor) {
        tenantExecution.run(tenant, () -> jdbc.update("""
                update ai_grid_budget_alerts set status = 'ACKNOWLEDGED',
                    acknowledged_by = :actor, acknowledged_at = now()
                 where id = :id and status = 'OPEN'
                """, Map.of("actor", actor, "id", alertId)));
    }

    private BudgetConfig current() {
        return jdbc.queryForObject("select * from ai_grid_budget_config", Map.of(), (rs, n) -> new BudgetConfig(
                rs.getString("enforcement_mode"), number(rs, "daily_scan_limit"),
                number(rs, "daily_provider_api_call_limit"), number(rs, "daily_new_snapshot_bytes_limit"),
                number(rs, "daily_processing_ms_limit"), number(rs, "retained_snapshot_bytes_limit"),
                rs.getDouble("warning_ratio"), rs.getString("updated_by"), rs.getString("reason"),
                rs.getTimestamp("updated_at").toInstant()));
    }

    private BudgetUsage usage() {
        return jdbc.queryForObject("""
                select
                    (select count(*) from ai_grid_budget_admissions
                      where decision = 'ADMITTED' and admitted_at >= date_trunc('day', now())) scans,
                    (select coalesce(sum(provider_api_calls), 0) from ai_grid_run_metrics
                      where first_recorded_at >= date_trunc('day', now())) calls,
                    (select coalesce(sum(new_snapshot_bytes), 0) from ai_grid_run_metrics
                      where first_recorded_at >= date_trunc('day', now())) new_bytes,
                    (select coalesce(sum(processing_duration_ms), 0) from ai_grid_run_metrics
                      where first_recorded_at >= date_trunc('day', now())) processing,
                    (select coalesce(sum(byte_size), 0) from ai_grid_snapshot_bodies
                      where retention_state <> 'PURGED') retained
                """, Map.of(), (rs, n) -> new BudgetUsage(rs.getLong("scans"), rs.getLong("calls"),
                rs.getLong("new_bytes"), rs.getLong("processing"), rs.getLong("retained")));
    }

    private List<String> exceeded(BudgetConfig config, BudgetUsage usage, boolean onlyHard) {
        List<String> values = new ArrayList<>();
        addExceeded(values, "DAILY_SCANS", usage.dailyScans(), config.dailyScanLimit(), config.warningRatio(), onlyHard);
        addExceeded(values, "PROVIDER_API_CALLS", usage.dailyProviderApiCalls(),
                config.dailyProviderApiCallLimit(), config.warningRatio(), onlyHard);
        addExceeded(values, "NEW_SNAPSHOT_BYTES", usage.dailyNewSnapshotBytes(),
                config.dailyNewSnapshotBytesLimit(), config.warningRatio(), onlyHard);
        addExceeded(values, "PROCESSING_MS", usage.dailyProcessingMs(),
                config.dailyProcessingMsLimit(), config.warningRatio(), onlyHard);
        addExceeded(values, "RETAINED_SNAPSHOT_BYTES", usage.retainedSnapshotBytes(),
                config.retainedSnapshotBytesLimit(), config.warningRatio(), onlyHard);
        return values;
    }

    private void addExceeded(List<String> values, String metric, long observed, Long limit,
                             double warningRatio, boolean onlyHard) {
        if (limit == null) return;
        if (observed >= limit) values.add(metric + "_EXCEEDED");
        else if (!onlyHard && observed >= Math.floor(limit * warningRatio)) values.add(metric + "_WARNING");
    }

    private java.util.Optional<String> cadenceBlocker(String provider, List<String> families,
                                                       String environment, String criticality) {
        List<CadenceRule> rules = cadenceRules().stream().filter(CadenceRule::enabled)
                .filter(rule -> rule.provider().equals("*") || rule.provider().equalsIgnoreCase(provider))
                .filter(rule -> "*".equals(rule.environment()) || rule.environment().equalsIgnoreCase(wildcard(environment)))
                .filter(rule -> "*".equals(rule.criticality()) || rule.criticality().equalsIgnoreCase(wildcard(criticality)))
                .filter(rule -> "*".equals(rule.resourceFamily()) || (families != null && families.stream()
                        .anyMatch(family -> rule.resourceFamily().equalsIgnoreCase(family))))
                .toList();
        long minimum = rules.stream().mapToLong(CadenceRule::minimumIntervalSeconds).max().orElse(0);
        if (minimum == 0) return java.util.Optional.empty();
        Instant latest = jdbc.query("""
                select max(admitted_at) from ai_grid_budget_admissions
                 where provider = :provider and decision = 'ADMITTED'
                """, Map.of("provider", provider), rs -> rs.next() && rs.getTimestamp(1) != null
                ? rs.getTimestamp(1).toInstant() : null);
        return latest != null && latest.plusSeconds(minimum).isAfter(Instant.now())
                ? java.util.Optional.of("CADENCE_NOT_DUE") : java.util.Optional.empty();
    }

    private List<CadenceRule> cadenceRules() {
        return jdbc.query("select * from ai_grid_scan_cadence_rules order by provider, resource_family",
                (rs, n) -> new CadenceRule(rs.getObject("id", UUID.class), rs.getString("provider"),
                        rs.getString("resource_family"), rs.getString("environment"), rs.getString("criticality"),
                        rs.getLong("minimum_interval_seconds"), rs.getBoolean("enabled")));
    }

    private List<BudgetAlert> alerts() {
        return jdbc.query("""
                select id, run_id, metric, level, observed_value, limit_value, status,
                       first_observed_at, last_observed_at
                  from ai_grid_budget_alerts where status in ('OPEN','ACKNOWLEDGED')
                 order by level desc, last_observed_at desc
                """, (rs, n) -> new BudgetAlert(rs.getObject("id", UUID.class), rs.getObject("run_id", UUID.class),
                rs.getString("metric"), rs.getString("level"), rs.getLong("observed_value"),
                rs.getLong("limit_value"), rs.getString("status"),
                rs.getTimestamp("first_observed_at").toInstant(), rs.getTimestamp("last_observed_at").toInstant()));
    }

    private void reconcileAlerts(UUID runId, BudgetConfig config, BudgetUsage usage) {
        reconcileAlert(runId, "DAILY_SCANS", usage.dailyScans(), config.dailyScanLimit(), config.warningRatio());
        reconcileAlert(runId, "PROVIDER_API_CALLS", usage.dailyProviderApiCalls(),
                config.dailyProviderApiCallLimit(), config.warningRatio());
        reconcileAlert(runId, "NEW_SNAPSHOT_BYTES", usage.dailyNewSnapshotBytes(),
                config.dailyNewSnapshotBytesLimit(), config.warningRatio());
        reconcileAlert(runId, "PROCESSING_MS", usage.dailyProcessingMs(),
                config.dailyProcessingMsLimit(), config.warningRatio());
        reconcileAlert(runId, "RETAINED_SNAPSHOT_BYTES", usage.retainedSnapshotBytes(),
                config.retainedSnapshotBytesLimit(), config.warningRatio());
    }

    private void reconcileAlert(UUID runId, String metric, long observed, Long limit, double warningRatio) {
        if (limit == null || observed < Math.floor(limit * warningRatio)) {
            jdbc.update("""
                    update ai_grid_budget_alerts set status = 'RESOLVED', last_observed_at = now()
                     where metric = :metric and status in ('OPEN','ACKNOWLEDGED')
                    """, Map.of("metric", metric));
            return;
        }
        String level = observed >= limit ? "EXCEEDED" : "WARNING";
        int updated = jdbc.update("""
                update ai_grid_budget_alerts set run_id = :runId, level = :level,
                    observed_value = :observed, limit_value = :limit, last_observed_at = now()
                 where metric = :metric and status in ('OPEN','ACKNOWLEDGED')
                """, new MapSqlParameterSource().addValue("runId", runId).addValue("metric", metric)
                .addValue("level", level).addValue("observed", observed).addValue("limit", limit));
        if (updated == 0) {
            jdbc.update("""
                    insert into ai_grid_budget_alerts
                        (id, tenant_id, run_id, metric, level, observed_value, limit_value)
                    values (:id, current_setting('app.current_tenant_id')::uuid, :runId,
                            :metric, :level, :observed, :limit)
                    """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("runId", runId)
                    .addValue("metric", metric).addValue("level", level).addValue("observed", observed)
                    .addValue("limit", limit));
        }
    }

    private Long number(java.sql.ResultSet rs, String column) throws java.sql.SQLException {
        Object value = rs.getObject(column);
        return value == null ? null : ((Number) value).longValue();
    }

    private Long positive(Long value, String field) {
        if (value != null && value <= 0) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, field + " must be positive");
        return value;
    }
    private String required(String value, String field) {
        if (value == null || value.isBlank()) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, field + " is required");
        return value;
    }
    private String wildcard(String value) { return value == null || value.isBlank() ? "*" : value; }
    private String json(Object value) {
        try { return objectMapper.writeValueAsString(value); }
        catch (JsonProcessingException ex) { throw new IllegalArgumentException("Unable to serialize AI Grid budget state", ex); }
    }

    public record BudgetConfig(String enforcementMode, Long dailyScanLimit, Long dailyProviderApiCallLimit,
                               Long dailyNewSnapshotBytesLimit, Long dailyProcessingMsLimit,
                               Long retainedSnapshotBytesLimit, double warningRatio, String updatedBy,
                               String reason, Instant updatedAt) {}
    public record BudgetUsage(long dailyScans, long dailyProviderApiCalls, long dailyNewSnapshotBytes,
                              long dailyProcessingMs, long retainedSnapshotBytes) {}
    public record BudgetAlert(UUID id, UUID runId, String metric, String level, long observedValue,
                              long limitValue, String status, Instant firstObservedAt, Instant lastObservedAt) {}
    public record BudgetStatus(BudgetConfig config, BudgetUsage usage, List<BudgetAlert> alerts) {}
    public record Admission(UUID runId, String decision, String reasonCode, BudgetUsage usage) {}
    public record CadenceRule(UUID id, String provider, String resourceFamily, String environment,
                              String criticality, long minimumIntervalSeconds, boolean enabled) {}
    public record BudgetConfigCommand(String enforcementMode, Long dailyScanLimit,
                                      Long dailyProviderApiCallLimit, Long dailyNewSnapshotBytesLimit,
                                      Long dailyProcessingMsLimit, Long retainedSnapshotBytesLimit,
                                      double warningRatio, String reason) {}
    public record CadenceCommand(String provider, String resourceFamily, String environment, String criticality,
                                 long minimumIntervalSeconds, boolean enabled, String reason) {}

    public static final class BudgetExceededException extends RuntimeException {
        public BudgetExceededException(String reason) { super(reason); }
    }
}
