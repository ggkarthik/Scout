package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.migration.PackagedMigrationCatalog;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/** Numeric Program 2 entry gate measured from consequential runtime events. */
@Service
public class AiGridRuntimeTelemetryReadinessService {
    static final int WINDOW_DAYS = 14;
    static final double DECISION_FILL_THRESHOLD = 0.95;
    static final double AGENT_CORRELATION_THRESHOLD = 0.90;
    static final double VERSION_CORRELATION_THRESHOLD = 0.80;
    static final long MINIMUM_EXECUTIONS_PER_PROVIDER = 100;
    static final long MINIMUM_VERSION_APPLICABLE_EXECUTIONS = 50;
    private final NamedParameterJdbcTemplate jdbc;
    private final TenantSchemaExecutionService tenantExecution;
    private final int requiredTenantSchemaVersion;
    @Value("${app.ai-security.runtime.retention-days:90}")
    private int retentionDays = 90;
    @Value("${app.ai-security.runtime.estimated-storage-cost-usd-per-gib-month:0.023}")
    private double storageCostPerGibMonth = 0.023;

    public AiGridRuntimeTelemetryReadinessService(NamedParameterJdbcTemplate jdbc,
                                                   TenantSchemaExecutionService tenantExecution,
                                                   PackagedMigrationCatalog migrationCatalog) {
        this.jdbc = jdbc;
        this.tenantExecution = tenantExecution;
        this.requiredTenantSchemaVersion = migrationCatalog.tenantTarget();
    }

    public TelemetryReadiness readiness(Tenant tenant) {
        Instant from = Instant.now().minus(WINDOW_DAYS, ChronoUnit.DAYS);
        return tenantExecution.run(tenant, () -> {
            Integer tenantSchemaVersion = jdbc.query("""
                    select current_version
                      from platform.tenant_schema_versions
                     where tenant_id=:tenantId and status='CURRENT'
                    """, Map.of("tenantId", tenant.getId()),
                    rs -> rs.next() ? rs.getInt(1) : null);
            if (tenantSchemaVersion == null || tenantSchemaVersion < requiredTenantSchemaVersion) {
                return new TelemetryReadiness(from, Instant.now(), WINDOW_DAYS, DECISION_FILL_THRESHOLD,
                        AGENT_CORRELATION_THRESHOLD, VERSION_CORRELATION_THRESHOLD,
                        MINIMUM_EXECUTIONS_PER_PROVIDER, MINIMUM_VERSION_APPLICABLE_EXECUTIONS,
                        false, false, List.of("TENANT_SCHEMA_UPGRADE_REQUIRED"), List.of());
            }
            List<SourceReadiness> sources = jdbc.query("""
                    with configured_sources as (
                        select c.source_id,c.provider,c.source_kind,c.required_for_program_gate,
                               case when c.source_kind='PROVIDER_CONNECTOR'
                                    then coalesce(f.enabled and not f.kill_switch,false)
                                    else true end configured,
                               null::varchar evidence_class,
                               null::varchar certification_state
                          from ai_runtime_source_configurations c
                          left join ai_security_connector_feature_flags f on f.feature_key=c.feature_key
                         where c.status='ACTIVE'
                        union all
                        select p.producer_id,p.provider,'TELEMETRY_ADAPTER',false,
                               p.status='ACTIVE',p.submitted_evidence_class,p.certification_state
                          from ai_runtime_evidence_producers p
                    ), execution_stats as (
                        select provider,source,count(*) executions,
                               count(*) filter (where approval_state is not null) execution_approval_populated,
                               count(*) filter (where policy_state is not null) execution_policy_populated,
                               count(*) filter (where agent_artifact_id is not null) agent_correlated,
                               count(*) filter (where provider_agent_version_digest is not null) version_applicable,
                               count(*) filter (where provider_agent_version_digest is not null
                                   and agent_version_artifact_id is not null) version_correlated,
                               avg(delivery_latency_ms) filter (where delivery_latency_ms is not null) average_delivery_latency_ms
                          from ai_agent_executions
                         where evidence_time >= :from
                         group by provider,source
                    ), event_stats as (
                        select e.provider,e.source,
                               count(*) filter (where v.action_category in
                                   ('WRITE','DELETE','SEND','EXECUTE','ADMIN','PAYMENT','PUBLISH')) consequential_events,
                               count(*) filter (where v.action_category in
                                   ('WRITE','DELETE','SEND','EXECUTE','ADMIN','PAYMENT','PUBLISH')
                                   and v.approval_state is not null) approval_populated,
                               count(*) filter (where v.action_category in
                                   ('WRITE','DELETE','SEND','EXECUTE','ADMIN','PAYMENT','PUBLISH')
                                   and v.policy_state is not null) policy_populated,
                               count(*) filter (where v.action_category in
                                   ('WRITE','DELETE','SEND','EXECUTE','ADMIN','PAYMENT','PUBLISH')
                                   and v.action_outcome is not null) outcome_populated
                          from ai_agent_executions e
                          join ai_agent_execution_events v on v.execution_id=e.id and v.tenant_id=e.tenant_id
                         where e.evidence_time >= :from
                         group by e.provider,e.source
                    ), quota as (
                        select source_id,bool_or(quota_state='EXHAUSTED') quota_exhausted,
                               bool_or(quota_state='SOFT_LIMIT') quota_soft_limit,
                               sum(accepted_event_count) accepted_events,sum(accepted_byte_count) accepted_bytes
                          from ai_runtime_quota_windows
                         where window_end >= :from
                         group by source_id
                    ), receipt_stats as (
                        select producer_id,sum(accepted_count) accepted,sum(duplicate_count) duplicates,
                               sum(quarantined_count) quarantined,sum(request_byte_count) received_bytes,
                               sum(accepted_count+duplicate_count+quarantined_count) processed,
                               bool_or(status='FAILED') processing_failed,
                               bool_or(reason_code='HMAC_KEY_VERSION_MISMATCH') receipt_hmac_mismatch
                          from ai_runtime_ingestion_receipts
                         where created_at >= :from
                         group by producer_id
                    ), latest_capabilities as (
                        select distinct on (provider,capability_id,account_id,region)
                               provider,status,expires_at,detail
                          from ai_grid_capability_observations
                         order by provider,capability_id,account_id,region,observed_at desc,id desc
                    ), capability_alerts as (
                        select provider,
                               bool_or(status in ('ERROR','UNAUTHORIZED')) collection_failed,
                               bool_or(status='STALE' or expires_at is null or expires_at <= now()) capability_stale,
                               bool_or(detail ilike '%API_CALL_BUDGET_EXHAUSTED%'
                                   or detail ilike '%PROVIDER_CALL_BUDGET_EXHAUSTED%') api_budget_exhausted
                          from latest_capabilities group by provider
                    ), digest_alerts as (
                        select e.provider,e.source,
                               bool_or(v.digest_key_version is not null
                                   and v.digest_key_version <> e.digest_key_version) hmac_key_version_mismatch
                          from ai_agent_executions e
                          join ai_agent_execution_events v on v.execution_id=e.id and v.tenant_id=e.tenant_id
                         where e.evidence_time >= :from group by e.provider,e.source
                    ), evaluator_alert as (
                        select bool_or(reason_code='EVALUATION_BOUND_EXCEEDED') evaluator_budget_exhausted
                          from ai_grid_assessments where evaluated_at >= :from
                    ), retention_alert as (
                        select count(*) > 0 retention_backlog from ai_agent_executions
                         where evidence_time < now() - make_interval(days => :retentionDays)
                    )
                    select s.source_id,s.provider,s.source_kind,s.required_for_program_gate,s.configured,
                           s.evidence_class,s.certification_state,
                           coalesce(x.executions,0) executions,
                           coalesce(x.execution_approval_populated,0) execution_approval_populated,
                           coalesce(x.execution_policy_populated,0) execution_policy_populated,
                           coalesce(x.agent_correlated,0) agent_correlated,
                           coalesce(x.version_applicable,0) version_applicable,
                           coalesce(x.version_correlated,0) version_correlated,
                           coalesce(v.consequential_events,0) consequential_events,
                           coalesce(v.approval_populated,0) approval_populated,
                           coalesce(v.policy_populated,0) policy_populated,
                           coalesce(v.outcome_populated,0) outcome_populated,
                           coalesce(q.quota_exhausted,false) quota_exhausted,
                           coalesce(q.quota_soft_limit,false) quota_soft_limit,
                           coalesce(q.accepted_events,0) quota_accepted_events,
                           coalesce(q.accepted_bytes,0) quota_accepted_bytes,
                           coalesce(x.average_delivery_latency_ms,0) average_delivery_latency_ms,
                           coalesce(r.accepted,0) accepted,coalesce(r.duplicates,0) duplicates,
                           coalesce(r.quarantined,0) quarantined,coalesce(r.processed,0) processed,
                           coalesce(r.received_bytes,0) received_bytes,
                           coalesce(r.processing_failed,false) processing_failed,
                           coalesce(r.receipt_hmac_mismatch,false)
                               or coalesce(d.hmac_key_version_mismatch,false) hmac_key_version_mismatch,
                           coalesce(c.collection_failed,false) collection_failed,
                           coalesce(c.capability_stale,false) capability_stale,
                           coalesce(c.api_budget_exhausted,false) api_budget_exhausted,
                           coalesce(ea.evaluator_budget_exhausted,false) evaluator_budget_exhausted,
                           coalesce(ra.retention_backlog,false) retention_backlog
                      from configured_sources s
                      left join execution_stats x on x.provider=s.provider and x.source=s.source_id
                      left join event_stats v on v.provider=s.provider and v.source=s.source_id
                      left join quota q on q.source_id=s.source_id
                      left join receipt_stats r on r.producer_id=s.source_id
                      left join capability_alerts c on c.provider=s.provider
                      left join digest_alerts d on d.provider=s.provider and d.source=s.source_id
                      cross join evaluator_alert ea
                      cross join retention_alert ra
                     order by s.source_kind,s.provider,s.source_id
                    """, new MapSqlParameterSource("from", java.sql.Timestamp.from(from))
                            .addValue("retentionDays", Math.max(1, retentionDays)), (rs, row) -> {
                long executions = rs.getLong("executions");
                long consequentialEvents = rs.getLong("consequential_events");
                long versionApplicable = rs.getLong("version_applicable");
                double approvalFillRate = rate(rs.getLong("approval_populated"), consequentialEvents);
                double policyFillRate = rate(rs.getLong("policy_populated"), consequentialEvents);
                double outcomeFillRate = rate(rs.getLong("outcome_populated"), consequentialEvents);
                double executionApprovalFillRate = rate(rs.getLong("execution_approval_populated"), executions);
                double executionPolicyFillRate = rate(rs.getLong("execution_policy_populated"), executions);
                double agentCorrelationRate = rate(rs.getLong("agent_correlated"), executions);
                double versionCorrelationRate = rate(rs.getLong("version_correlated"), versionApplicable);
                double quarantineRate = rate(rs.getLong("quarantined"), rs.getLong("processed"));
                double duplicateRate = rate(rs.getLong("duplicates"), rs.getLong("processed"));
                boolean configured = rs.getBoolean("configured");
                boolean quotaExhausted = rs.getBoolean("quota_exhausted");
                boolean quotaSoftLimit = rs.getBoolean("quota_soft_limit");
                boolean ready = configured && !quotaExhausted
                        && executions >= MINIMUM_EXECUTIONS_PER_PROVIDER
                        && consequentialEvents > 0
                        && approvalFillRate >= DECISION_FILL_THRESHOLD
                        && policyFillRate >= DECISION_FILL_THRESHOLD
                        && outcomeFillRate >= DECISION_FILL_THRESHOLD
                        && agentCorrelationRate >= AGENT_CORRELATION_THRESHOLD
                        && versionApplicable >= MINIMUM_VERSION_APPLICABLE_EXECUTIONS
                        && versionCorrelationRate >= VERSION_CORRELATION_THRESHOLD;
                List<String> blockers = blockers(configured, quotaExhausted, executions, consequentialEvents,
                        approvalFillRate, policyFillRate, outcomeFillRate, agentCorrelationRate,
                        versionApplicable, versionCorrelationRate);
                List<String> alerts = new ArrayList<>();
                if (quotaSoftLimit) alerts.add("TENANT_QUOTA_SOFT_LIMIT");
                if (quotaExhausted) alerts.add("TENANT_QUOTA_EXHAUSTED");
                if (quarantineRate >= 0.05) alerts.add("QUARANTINE_RATE_ELEVATED");
                if (rs.getDouble("average_delivery_latency_ms") > 300000) alerts.add("DELIVERY_LAG_ELEVATED");
                if (rs.getBoolean("processing_failed")) alerts.add("COLLECTION_PROCESSING_FAILED");
                if (rs.getBoolean("hmac_key_version_mismatch")) alerts.add("HMAC_KEY_VERSION_MISMATCH");
                if (rs.getBoolean("collection_failed")) alerts.add("COLLECTION_FAILED");
                if (rs.getBoolean("capability_stale")) alerts.add("CAPABILITY_STALE");
                if (rs.getBoolean("api_budget_exhausted")) alerts.add("API_BUDGET_EXHAUSTED");
                if (rs.getBoolean("retention_backlog")) alerts.add("RETENTION_BACKLOG");
                if (rs.getBoolean("evaluator_budget_exhausted")) alerts.add("EVALUATOR_BUDGET_EXHAUSTED");
                double estimatedStorageCost = rs.getLong("quota_accepted_bytes")
                        / (1024d * 1024d * 1024d) * Math.max(0, storageCostPerGibMonth);
                return new SourceReadiness(rs.getString("source_id"), rs.getString("provider"),
                        rs.getString("source_kind"), rs.getBoolean("required_for_program_gate"), configured,
                        rs.getString("evidence_class"), rs.getString("certification_state"), executions,
                        consequentialEvents, approvalFillRate, policyFillRate, outcomeFillRate,
                        executionApprovalFillRate, executionPolicyFillRate, agentCorrelationRate,
                        versionCorrelationRate, versionApplicable, rs.getDouble("average_delivery_latency_ms"),
                        rs.getLong("accepted"), duplicateRate, quarantineRate, rs.getLong("received_bytes"),
                        rs.getLong("quota_accepted_events"), rs.getLong("quota_accepted_bytes"),
                        estimatedStorageCost,
                        quotaSoftLimit, quotaExhausted, ready, List.copyOf(blockers), List.copyOf(alerts));
            });
            List<SourceReadiness> requiredProviders = sources.stream()
                    .filter(source -> source.requiredForProgramGate()
                            && "PROVIDER_CONNECTOR".equals(source.sourceKind()))
                    .toList();
            boolean ready = requiredProviders.size() >= 2
                    && requiredProviders.stream().allMatch(SourceReadiness::entryGateMet);
            return new TelemetryReadiness(from, Instant.now(), WINDOW_DAYS, DECISION_FILL_THRESHOLD,
                    AGENT_CORRELATION_THRESHOLD, VERSION_CORRELATION_THRESHOLD,
                    MINIMUM_EXECUTIONS_PER_PROVIDER, MINIMUM_VERSION_APPLICABLE_EXECUTIONS,
                    true, ready, List.of(), sources);
        });
    }

    private static List<String> blockers(boolean configured, boolean quotaExhausted, long executions,
                                         long consequentialEvents, double approvalFillRate,
                                         double policyFillRate, double outcomeFillRate,
                                         double agentCorrelationRate, long versionApplicable,
                                         double versionCorrelationRate) {
        List<String> blockers = new ArrayList<>();
        if (!configured) {
            blockers.add("NOT_CONFIGURED");
            return blockers;
        }
        if (quotaExhausted) blockers.add("TENANT_QUOTA_EXHAUSTED");
        if (executions < MINIMUM_EXECUTIONS_PER_PROVIDER) blockers.add("MINIMUM_EXECUTIONS_NOT_MET");
        if (consequentialEvents == 0) blockers.add("CONSEQUENTIAL_EVENT_SAMPLE_INSUFFICIENT");
        if (approvalFillRate < DECISION_FILL_THRESHOLD) blockers.add("APPROVAL_STATE_FILL_BELOW_THRESHOLD");
        if (policyFillRate < DECISION_FILL_THRESHOLD) blockers.add("POLICY_STATE_FILL_BELOW_THRESHOLD");
        if (outcomeFillRate < DECISION_FILL_THRESHOLD) blockers.add("ACTION_OUTCOME_FILL_BELOW_THRESHOLD");
        if (agentCorrelationRate < AGENT_CORRELATION_THRESHOLD) blockers.add("AGENT_CORRELATION_BELOW_THRESHOLD");
        if (versionApplicable < MINIMUM_VERSION_APPLICABLE_EXECUTIONS) blockers.add("VERSION_SAMPLE_INSUFFICIENT");
        else if (versionCorrelationRate < VERSION_CORRELATION_THRESHOLD) {
            blockers.add("VERSION_CORRELATION_BELOW_THRESHOLD");
        }
        return blockers;
    }

    private static double rate(long numerator, long denominator) {
        return denominator == 0 ? 0 : numerator / (double) denominator;
    }

    public record TelemetryReadiness(Instant windowStart, Instant windowEnd, int windowDays,
                                     double minimumFillRate, double minimumAgentCorrelationRate,
                                     double minimumVersionCorrelationRate, long minimumExecutionsPerProvider,
                                     long minimumVersionApplicableExecutions,
                                     boolean available, boolean program2EntryGateMet,
                                     List<String> blockers, List<SourceReadiness> providers) {}

    public record SourceReadiness(String sourceId, String provider, String sourceKind,
                                  boolean requiredForProgramGate, boolean configured,
                                  String evidenceClass, String certificationState, long executions,
                                  long consequentialEvents, double approvalStateFillRate,
                                  double policyStateFillRate, double actionOutcomeFillRate,
                                  double executionApprovalStateFillRate, double executionPolicyStateFillRate,
                                  double agentCorrelationRate, double versionCorrelationRate,
                                  long versionApplicableExecutions, double averageDeliveryLatencyMs,
                                  long acceptedEvents, double duplicateRate, double quarantineRate,
                                  long receivedBytes, long quotaAcceptedEvents, long quotaAcceptedBytes,
                                  double estimatedStorageCostUsd,
                                  boolean quotaSoftLimit, boolean quotaExhausted,
                                  boolean entryGateMet, List<String> blockers, List<String> alerts) {}
}
