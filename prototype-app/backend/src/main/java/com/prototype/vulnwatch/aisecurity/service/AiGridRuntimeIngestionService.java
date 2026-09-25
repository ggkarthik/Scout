package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.IngestionJobAcceptedResponse;
import com.prototype.vulnwatch.service.IngestionJobService;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/** Governed, metadata-only admission boundary for customer runtime telemetry producers. */
@Service
public class AiGridRuntimeIngestionService {
    private static final Set<String> FORBIDDEN_FIELDS = Set.of(
            "prompt", "response", "argument", "arguments", "result", "results", "credential",
            "credentials", "document", "documentbody", "messagebody", "rawpayload", "requestbody",
            "responsebody", "content", "secret", "tokenvalue");
    private static final int MAX_BODY_BYTES = 2 * 1024 * 1024;
    private static final int MAX_EXECUTIONS = 100;

    private final NamedParameterJdbcTemplate jdbc;
    private final TenantSchemaExecutionService tenantExecution;
    private final TransactionTemplate transactions;
    private final IngestionJobService jobs;
    private final ObjectMapper mapper;
    private final int maximumBacklog;

    public AiGridRuntimeIngestionService(NamedParameterJdbcTemplate jdbc,
                                         TenantSchemaExecutionService tenantExecution,
                                         TransactionTemplate transactions,
                                         IngestionJobService jobs,
                                         ObjectMapper mapper,
                                         @Value("${app.ai-security.runtime.adapter.max-backlog-per-tenant:100}") int maximumBacklog) {
        this.jdbc = jdbc;
        this.tenantExecution = tenantExecution;
        this.transactions = transactions;
        this.jobs = jobs;
        this.mapper = mapper;
        this.maximumBacklog = Math.max(1, maximumBacklog);
    }

    public AdmissionResult accept(Tenant tenant, String producerId, byte[] body) {
        if (body == null || body.length == 0) throw new IllegalArgumentException("Runtime batch body is required");
        if (body.length > MAX_BODY_BYTES) throw new IllegalArgumentException("Runtime batch exceeds the 2 MiB limit");
        JsonNode tree = parse(body);
        rejectForbiddenFields(tree);
        RuntimeBatch batch = convert(tree, RuntimeBatch.class);
        validateBatch(batch);
        long eventCount = batch.executions().stream().mapToLong(item -> item.events().size()).sum();
        return tenantExecution.run(tenant, () -> transactions.execute(status ->
                admit(tenant, producerId, tree, batch, body.length, eventCount)));
    }

    public Receipt receipt(Tenant tenant, UUID receiptId) {
        return tenantExecution.run(tenant, () -> jdbc.query("""
                select id,producer_id,status,accepted_count,duplicate_count,quarantined_count,reason_code,
                       ingestion_job_id,request_byte_count,request_event_count,created_at,completed_at
                  from ai_runtime_ingestion_receipts
                 where tenant_id=:tenantId and id=:id
                """, new MapSqlParameterSource().addValue("tenantId", tenant.getId()).addValue("id", receiptId),
                rs -> rs.next() ? mapReceipt(rs) : null));
    }

    private AdmissionResult admit(Tenant tenant, String producerId, JsonNode tree, RuntimeBatch batch,
                                  long byteCount, long eventCount) {
        Producer producer = requireProducer(tenant, producerId);
        if (!producer.provider().equals(batch.provider())) {
            throw new AccessDeniedException("Runtime producer is not registered for the submitted provider");
        }
        if ("AUTHORITATIVE".equals(batch.evidenceClass()) && !"CERTIFIED".equals(producer.certificationState())) {
            throw new AccessDeniedException("Uncertified runtime producer cannot submit AUTHORITATIVE evidence");
        }
        if (!"AUTHORITATIVE".equals(batch.evidenceClass())
                && !producer.submittedEvidenceClass().equals(batch.evidenceClass())) {
            throw new AccessDeniedException("Submitted evidence class does not match producer registration");
        }
        for (RuntimeExecutionInput execution : batch.executions()) {
            if (!batch.evidenceClass().equals(execution.evidenceClass())) {
                throw new IllegalArgumentException("Every execution evidenceClass must match the batch evidenceClass");
            }
        }

        UUID receiptId = UUID.randomUUID();
        Long backlog = jdbc.queryForObject("""
                select count(*) from ingestion_jobs
                 where job_type=:type and status in ('QUEUED','RUNNING')
                """, Map.of("type", IngestionJobService.JOB_TYPE_AI_GRID_RUNTIME_ADAPTER), Long.class);
        if (backlog != null && backlog >= maximumBacklog) {
            insertReceipt(tenant, producerId, receiptId, "REJECTED", "INGESTION_CAPACITY_EXHAUSTED",
                    byteCount, eventCount, 0, 0, 0, null, Instant.now());
            return new AdmissionResult(receiptId, "REJECTED", 0, 0, 0,
                    "INGESTION_CAPACITY_EXHAUSTED", 30);
        }

        QuotaDecision quota = reserveQuota(tenant, producerId, byteCount, eventCount);
        if (quota.exhausted()) {
            insertReceipt(tenant, producerId, receiptId, "REJECTED", "TENANT_QUOTA_EXHAUSTED",
                    byteCount, eventCount, 0, 0, 0, null, Instant.now());
            return new AdmissionResult(receiptId, "REJECTED", 0, 0, 0,
                    "TENANT_QUOTA_EXHAUSTED", quota.retryAfterSeconds());
        }

        insertReceipt(tenant, producerId, receiptId, "ACCEPTED", null, byteCount, eventCount,
                batch.executions().size(), 0, 0, null, null);
        IngestionJobAcceptedResponse job = jobs.enqueueRuntimeAdapterJob(tenant, producerId, receiptId, tree);
        jdbc.update("update ai_runtime_ingestion_receipts set ingestion_job_id=:jobId where id=:id and tenant_id=:tenantId",
                new MapSqlParameterSource().addValue("jobId", job.jobId()).addValue("id", receiptId)
                        .addValue("tenantId", tenant.getId()));
        return new AdmissionResult(receiptId, "ACCEPTED", batch.executions().size(), 0, 0,
                quota.softLimit() ? "TENANT_QUOTA_SOFT_LIMIT" : null, null);
    }

    private Producer requireProducer(Tenant tenant, String producerId) {
        Producer producer = jdbc.query("""
                select p.provider,p.submitted_evidence_class,p.certification_state
                  from ai_runtime_evidence_producers p
                  join service_accounts s on s.id=p.service_account_id and s.tenant_id=p.tenant_id
                 where p.producer_id=:producerId and p.tenant_id=:tenantId
                   and p.producer_type='RUNTIME_EVIDENCE_PRODUCER'
                   and p.status='ACTIVE' and s.status='ACTIVE'
                """, new MapSqlParameterSource().addValue("producerId", producerId)
                .addValue("tenantId", tenant.getId()), rs -> rs.next()
                ? new Producer(rs.getString(1), rs.getString(2), rs.getString(3)) : null);
        if (producer == null) throw new AccessDeniedException("Runtime evidence producer is inactive or unregistered for this tenant");
        return producer;
    }

    private QuotaDecision reserveQuota(Tenant tenant, String sourceId, long byteCount, long eventCount) {
        QuotaConfig config = jdbc.query("""
                select runtime_quota_window_seconds,rolling_runtime_event_limit,rolling_runtime_byte_limit
                  from ai_grid_budget_config limit 1
                """, Map.of(), rs -> rs.next() ? new QuotaConfig(rs.getLong(1), (Long) rs.getObject(2),
                (Long) rs.getObject(3)) : new QuotaConfig(86400, null, null));
        long window = Math.max(1, config.windowSeconds());
        Instant now = Instant.now();
        Instant start = Instant.ofEpochSecond((now.getEpochSecond() / window) * window).truncatedTo(ChronoUnit.SECONDS);
        Instant end = start.plusSeconds(window);
        MapSqlParameterSource values = new MapSqlParameterSource().addValue("id", UUID.randomUUID())
                .addValue("tenantId", tenant.getId()).addValue("sourceId", sourceId)
                .addValue("start", Timestamp.from(start)).addValue("end", Timestamp.from(end));
        jdbc.update("""
                insert into ai_runtime_quota_windows(id,tenant_id,source_id,window_start,window_end)
                values (:id,:tenantId,:sourceId,:start,:end)
                on conflict (tenant_id,source_id,window_start) do nothing
                """, values);
        QuotaUsage usage = jdbc.query("""
                select id,accepted_event_count,accepted_byte_count
                  from ai_runtime_quota_windows
                 where tenant_id=:tenantId and source_id=:sourceId and window_start=:start
                 for update
                """, values, rs -> {
            if (!rs.next()) throw new IllegalStateException("Runtime quota window is unavailable");
            return new QuotaUsage(rs.getObject(1, UUID.class), rs.getLong(2), rs.getLong(3));
        });
        long projectedEvents = Math.addExact(usage.events(), eventCount);
        long projectedBytes = Math.addExact(usage.bytes(), byteCount);
        boolean exhausted = exceeds(projectedEvents, config.eventLimit()) || exceeds(projectedBytes, config.byteLimit());
        boolean soft = !exhausted && (atSoftLimit(projectedEvents, config.eventLimit())
                || atSoftLimit(projectedBytes, config.byteLimit()));
        jdbc.update("""
                update ai_runtime_quota_windows set
                    accepted_event_count=accepted_event_count+:acceptedEvents,
                    accepted_byte_count=accepted_byte_count+:acceptedBytes,
                    rejected_event_count=rejected_event_count+:rejectedEvents,
                    rejected_byte_count=rejected_byte_count+:rejectedBytes,
                    quota_state=:state,updated_at=now()
                 where id=:id
                """, new MapSqlParameterSource().addValue("acceptedEvents", exhausted ? 0 : eventCount)
                .addValue("acceptedBytes", exhausted ? 0 : byteCount)
                .addValue("rejectedEvents", exhausted ? eventCount : 0)
                .addValue("rejectedBytes", exhausted ? byteCount : 0)
                .addValue("state", exhausted ? "EXHAUSTED" : soft ? "SOFT_LIMIT" : "AVAILABLE")
                .addValue("id", usage.id()));
        long retrySeconds = Math.max(1, end.getEpochSecond() - now.getEpochSecond());
        return new QuotaDecision(exhausted, soft,
                exhausted ? (int) Math.min(Integer.MAX_VALUE, retrySeconds) : null);
    }

    private void insertReceipt(Tenant tenant, String producerId, UUID id, String status, String reason,
                               long bytes, long events, int accepted, int duplicates, int quarantined,
                               UUID jobId, Instant completedAt) {
        jdbc.update("""
                insert into ai_runtime_ingestion_receipts
                    (id,tenant_id,producer_id,status,accepted_count,duplicate_count,quarantined_count,
                     reason_code,ingestion_job_id,request_byte_count,request_event_count,completed_at)
                values (:id,:tenantId,:producerId,:status,:accepted,:duplicates,:quarantined,
                        :reason,:jobId,:bytes,:events,:completedAt)
                """, new MapSqlParameterSource().addValue("id", id).addValue("tenantId", tenant.getId())
                .addValue("producerId", producerId).addValue("status", status).addValue("accepted", accepted)
                .addValue("duplicates", duplicates).addValue("quarantined", quarantined).addValue("reason", reason)
                .addValue("jobId", jobId).addValue("bytes", bytes).addValue("events", events)
                .addValue("completedAt", completedAt == null ? null : Timestamp.from(completedAt)));
    }

    private Receipt mapReceipt(java.sql.ResultSet rs) throws java.sql.SQLException {
        Timestamp completed = rs.getTimestamp("completed_at");
        return new Receipt(rs.getObject("id", UUID.class), rs.getString("producer_id"), rs.getString("status"),
                rs.getInt("accepted_count"), rs.getInt("duplicate_count"), rs.getInt("quarantined_count"),
                rs.getString("reason_code"), rs.getObject("ingestion_job_id", UUID.class),
                rs.getLong("request_byte_count"), rs.getLong("request_event_count"),
                rs.getTimestamp("created_at").toInstant(), completed == null ? null : completed.toInstant());
    }

    private JsonNode parse(byte[] body) {
        try { return mapper.readTree(body); }
        catch (Exception error) { throw new IllegalArgumentException("Runtime batch is not valid JSON", error); }
    }

    private <T> T convert(JsonNode value, Class<T> type) {
        try { return mapper.treeToValue(value, type); }
        catch (Exception error) { throw new IllegalArgumentException("Runtime batch does not match schema v1", error); }
    }

    private void validateBatch(RuntimeBatch batch) {
        if (batch == null || !"1".equals(batch.schemaVersion()) || blank(batch.provider())
                || blank(batch.evidenceClass()) || batch.executions() == null
                || batch.executions().isEmpty() || batch.executions().size() > MAX_EXECUTIONS) {
            throw new IllegalArgumentException("Runtime batch requires schemaVersion 1, provider, evidenceClass, and 1-100 executions");
        }
        for (RuntimeExecutionInput execution : batch.executions()) {
            if (execution == null || blank(execution.providerExecutionReference()) || execution.eventTime() == null
                    || blank(execution.scopeKey()) || blank(execution.status()) || blank(execution.evidenceClass())) {
                throw new IllegalArgumentException("Every runtime execution requires providerExecutionReference, eventTime, scopeKey, status, and evidenceClass");
            }
            if (execution.events() == null) {
                throw new IllegalArgumentException("Runtime execution events must be present; use [] for metadata-only execution");
            }
        }
    }

    private void rejectForbiddenFields(JsonNode node) {
        if (node == null) return;
        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                String normalized = field.getKey().replace("_", "").replace("-", "").toLowerCase(Locale.ROOT);
                if (FORBIDDEN_FIELDS.contains(normalized)) {
                    throw new IllegalArgumentException("Forbidden raw-content field in runtime batch: " + field.getKey());
                }
                rejectForbiddenFields(field.getValue());
            }
        } else if (node.isArray()) node.forEach(this::rejectForbiddenFields);
    }

    private static boolean blank(String value) { return value == null || value.isBlank(); }
    private static boolean exceeds(long value, Long limit) { return limit != null && value > limit; }
    private static boolean atSoftLimit(long value, Long limit) { return limit != null && value * 100 >= limit * 80; }

    public record RuntimeBatch(String schemaVersion, String provider, String evidenceClass,
                               List<RuntimeExecutionInput> executions) { }
    public record RuntimeExecutionInput(
            String providerExecutionReference, String scopeKey, Instant eventTime, Instant startedAt,
            Instant completedAt, String status, String outcomeCategory, String approvalState, String policyState,
            String classification, String apiVersion, Long tokenCount, Long latencyMs, Integer retryCount,
            Long spendMicros, UUID agentArtifactId, UUID agentVersionArtifactId, String providerAgentReference,
            String providerAgentVersionReference, String correlationStatus, String correlationDiagnostic,
            String environmentReference, String deploymentReference, String actingIdentityReference,
            String delegatedIdentityReference, String terminationReason, String evidenceSource,
            String evidenceClass, Double evidenceConfidence, Long stepCount, String spendCurrency,
            String spendUnit, Instant collectedAt, Instant providerEventTime, Long deliveryLatencyMs,
            List<AiAgentExecutionIngestionService.RuntimeEvent> events) { }
    public record AdmissionResult(UUID receiptId, String status, int acceptedCount, int duplicateCount,
                                  int quarantinedCount, String reasonCode, Integer retryAfterSeconds) { }
    public record Receipt(UUID receiptId, String producerId, String status, int acceptedCount,
                          int duplicateCount, int quarantinedCount, String reasonCode, UUID ingestionJobId,
                          long requestByteCount, long requestEventCount, Instant createdAt, Instant completedAt) { }
    private record Producer(String provider, String submittedEvidenceClass, String certificationState) { }
    private record QuotaConfig(long windowSeconds, Long eventLimit, Long byteLimit) { }
    private record QuotaUsage(UUID id, long events, long bytes) { }
    private record QuotaDecision(boolean exhausted, boolean softLimit, Integer retryAfterSeconds) { }
}
