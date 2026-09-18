package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

/** Approval boundary for HMACed prompt and tool-definition content. Plaintext never enters this API. */
@Service
public class AiSecurityDigestBaselineService {
    private static final java.util.Set<String> KINDS = java.util.Set.of("PROMPT", "TOOL_DEFINITION");
    private final NamedParameterJdbcTemplate jdbc;
    private final TenantSchemaExecutionService tenantExecution;
    private final TransactionTemplate transactions;
    private final AuditEventService audit;
    private final AiGridFindingService findings;

    public AiSecurityDigestBaselineService(NamedParameterJdbcTemplate jdbc,
                                           TenantSchemaExecutionService tenantExecution,
                                           TransactionTemplate transactions,
                                           AuditEventService audit, AiGridFindingService findings) {
        this.jdbc = jdbc;
        this.tenantExecution = tenantExecution;
        this.transactions = transactions;
        this.audit = audit;
        this.findings = findings;
    }

    public List<Response> list(Tenant tenant, UUID artifactId) {
        return tenantExecution.run(tenant, () -> jdbc.query("""
                select artifact_id,digest_kind,algorithm,key_version,approval_status,approved_by,
                       approved_at,revoked_by,revoked_at,source_run_id,updated_at
                  from ai_security_artifact_digest_baselines
                 where artifact_id=:artifactId
                 order by digest_kind
                """, Map.of("artifactId", artifactId), (rs, row) -> new Response(
                rs.getObject("artifact_id", UUID.class), rs.getString("digest_kind"),
                rs.getString("algorithm"), rs.getString("key_version"), rs.getString("approval_status"),
                rs.getString("approved_by"), instant(rs.getTimestamp("approved_at")),
                rs.getString("revoked_by"), instant(rs.getTimestamp("revoked_at")),
                rs.getObject("source_run_id", UUID.class), rs.getTimestamp("updated_at").toInstant())));
    }

    public Response approve(Tenant tenant, UUID artifactId, Request request, String actor, boolean reapproval) {
        validate(request);
        Response response = tenantExecution.run(tenant, () -> transactions.execute(status -> {
            assertArtifact(tenant, artifactId);
            int existing = jdbc.queryForObject("""
                    select count(*) from ai_security_artifact_digest_baselines
                     where artifact_id=:artifactId and digest_kind=:kind
                    """, Map.of("artifactId", artifactId, "kind", request.digestKind()), Integer.class);
            if (!reapproval && existing > 0) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Digest baseline already exists; use reapprove");
            }
            if (reapproval && existing == 0) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Digest baseline does not exist; use approve");
            }
            jdbc.update("""
                    insert into ai_security_artifact_digest_baselines
                        (id,tenant_id,artifact_id,digest_kind,algorithm,key_version,approved_digest,
                         approval_status,approved_by,approved_at,source_run_id)
                    values (:id,:tenantId,:artifactId,:kind,:algorithm,:keyVersion,:digest,
                            'APPROVED',:actor,now(),:sourceRunId)
                    on conflict (tenant_id,artifact_id,digest_kind) do update set
                        algorithm=excluded.algorithm,key_version=excluded.key_version,
                        approved_digest=excluded.approved_digest,approval_status='APPROVED',
                        approved_by=excluded.approved_by,approved_at=now(),revoked_by=null,revoked_at=null,
                        source_run_id=excluded.source_run_id,updated_at=now()
                    """, params(tenant, artifactId, request, actor));
            resolveSetupActions(artifactId, request.digestKind());
            return required(artifactId, request.digestKind());
        }));
        audit.record(reapproval ? "ai_security.digest_baseline.reapproved" : "ai_security.digest_baseline.approved",
                "ai_security_artifact", artifactId.toString(), "{\"digestKind\":\"" + request.digestKind() + "\"}");
        return response;
    }

    public Response revoke(Tenant tenant, UUID artifactId, String digestKind, String actor) {
        requireKind(digestKind);
        Response response = tenantExecution.run(tenant, () -> transactions.execute(status -> {
            int changed = jdbc.update("""
                    update ai_security_artifact_digest_baselines
                       set approval_status='REVOKED',revoked_by=:actor,revoked_at=now(),updated_at=now()
                     where artifact_id=:artifactId and digest_kind=:kind and approval_status='APPROVED'
                    """, new MapSqlParameterSource().addValue("actor", actor).addValue("artifactId", artifactId)
                    .addValue("kind", digestKind));
            if (changed != 1) throw new ResponseStatusException(HttpStatus.CONFLICT, "Active digest baseline was not found");
            return required(artifactId, digestKind);
        }));
        audit.record("ai_security.digest_baseline.revoked", "ai_security_artifact", artifactId.toString(),
                "{\"digestKind\":\"" + digestKind + "\"}");
        return response;
    }

    /** Called inside observation ingestion. It records state, but never mutates an approved baseline. */
    public Outcome observeCurrentTenant(Tenant tenant, UUID artifactId, String digestKind, String algorithm,
                                        String keyVersion, String digest, UUID sourceRunId, Instant observedAt) {
        if (digest == null || digest.isBlank()) return null;
        requireKind(digestKind);
        Baseline baseline = jdbc.query("""
                select algorithm,key_version,approved_digest,approval_status
                  from ai_security_artifact_digest_baselines
                 where artifact_id=:artifactId and digest_kind=:kind
                """, Map.of("artifactId", artifactId, "kind", digestKind),
                rs -> rs.next() ? new Baseline(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4)) : null);
        Outcome outcome = comparison(baseline == null ? null : baseline.status(),
                baseline == null ? null : baseline.algorithm(), baseline == null ? null : baseline.keyVersion(),
                baseline == null ? null : baseline.digest(), algorithm, keyVersion, digest);

        jdbc.update("""
                insert into ai_security_artifact_digest_observations
                    (tenant_id,artifact_id,digest_kind,algorithm,key_version,observed_digest,
                     comparison_outcome,source_run_id,observed_at)
                values (:tenantId,:artifactId,:kind,:algorithm,:keyVersion,:digest,:outcome,:runId,:observedAt)
                on conflict (tenant_id,artifact_id,digest_kind) do update set
                    algorithm=excluded.algorithm,key_version=excluded.key_version,observed_digest=excluded.observed_digest,
                    comparison_outcome=excluded.comparison_outcome,source_run_id=excluded.source_run_id,
                    observed_at=excluded.observed_at
                """, new MapSqlParameterSource().addValue("tenantId", tenant.getId()).addValue("artifactId", artifactId)
                .addValue("kind", digestKind).addValue("algorithm", algorithm).addValue("keyVersion", keyVersion)
                .addValue("digest", digest).addValue("outcome", outcome.name()).addValue("runId", sourceRunId)
                .addValue("observedAt", Timestamp.from(observedAt)));
        if (outcome == Outcome.CHANGED_AFTER_APPROVAL || outcome == Outcome.BASELINE_UNKNOWN_REAPPROVAL_REQUIRED) {
            upsertSetupAction(tenant, artifactId, digestKind, sourceRunId, outcome);
        } else if (outcome == Outcome.UNCHANGED) {
            resolveSetupActions(artifactId, digestKind);
        }
        // Only a same-key digest change is policy drift. Key rotation and missing approval are
        // setup/coverage states and deliberately cannot create this finding.
        if (outcome == Outcome.CHANGED_AFTER_APPROVAL || outcome == Outcome.UNCHANGED) {
            String fingerprint = sha256("AI_ARTIFACT_DIGEST_CHANGED_AFTER_APPROVAL|" + artifactId + "|" + digestKind);
            findings.reconcile(tenant, new AiGridFindingService.AssessmentResult(UUID.randomUUID(), sourceRunId,
                    "AI_ARTIFACT_DIGEST_CHANGED_AFTER_APPROVAL", "1.0.0", "Approved AI definition changed",
                    "HIGH", "ENABLED", outcome == Outcome.CHANGED_AFTER_APPROVAL ? "FAIL" : "PASS",
                    outcome.name(), artifactId, fingerprint, Map.of("digestKind", digestKind,
                    "changedAfterApproval", outcome == Outcome.CHANGED_AFTER_APPROVAL)));
        }
        return outcome;
    }

    private void upsertSetupAction(Tenant tenant, UUID artifactId, String kind, UUID runId, Outcome outcome) {
        String fingerprint = sha256("digest-baseline|" + artifactId + "|" + kind);
        jdbc.update("""
                insert into ai_grid_setup_actions
                    (id,tenant_id,run_id,artifact_id,fingerprint,priority,category,action_code,title,detail,evidence_key)
                values (:id,:tenantId,:runId,:artifactId,:fingerprint,90,'DIGEST_APPROVAL','REAPPROVE_DIGEST_BASELINE',
                        'Reapprove artifact digest','The approved digest can no longer be used for this artifact.',:evidenceKey)
                on conflict (tenant_id,fingerprint) do update set
                    run_id=excluded.run_id,status='OPEN',last_observed_at=now(),resolved_at=null,
                    detail=excluded.detail
                """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                .addValue("runId", runId).addValue("artifactId", artifactId).addValue("fingerprint", fingerprint)
                .addValue("evidenceKey", "digest:" + kind + ":" + outcome.name()));
    }

    private void resolveSetupActions(UUID artifactId, String kind) {
        jdbc.update("""
                update ai_grid_setup_actions set status='RESOLVED',resolved_at=now(),last_observed_at=now()
                 where artifact_id=:artifactId and action_code='REAPPROVE_DIGEST_BASELINE'
                   and evidence_key like :evidencePrefix and status='OPEN'
                """, Map.of("artifactId", artifactId, "evidencePrefix", "digest:" + kind + ":%"));
    }

    private Response required(UUID artifactId, String kind) {
        return jdbc.query("""
                select artifact_id,digest_kind,algorithm,key_version,approval_status,approved_by,
                       approved_at,revoked_by,revoked_at,source_run_id,updated_at
                  from ai_security_artifact_digest_baselines where artifact_id=:artifactId and digest_kind=:kind
                """, Map.of("artifactId", artifactId, "kind", kind), rs -> {
            if (!rs.next()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Digest baseline was not found");
            return new Response(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3), rs.getString(4),
                    rs.getString(5), rs.getString(6), instant(rs.getTimestamp(7)), rs.getString(8),
                    instant(rs.getTimestamp(9)), rs.getObject(10, UUID.class), rs.getTimestamp(11).toInstant());
        });
    }

    private void assertArtifact(Tenant tenant, UUID artifactId) {
        Integer count = jdbc.queryForObject("select count(*) from ai_security_artifacts where id=:id and tenant_id=:tenantId",
                Map.of("id", artifactId, "tenantId", tenant.getId()), Integer.class);
        if (count == null || count != 1) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "AI artifact was not found");
    }

    private static MapSqlParameterSource params(Tenant tenant, UUID artifactId, Request request, String actor) {
        return new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                .addValue("artifactId", artifactId).addValue("kind", request.digestKind())
                .addValue("algorithm", request.algorithm()).addValue("keyVersion", request.keyVersion())
                .addValue("digest", request.digest()).addValue("actor", actor).addValue("sourceRunId", request.sourceRunId());
    }

    private static void validate(Request request) {
        if (request == null || blank(request.algorithm()) || blank(request.keyVersion()) || blank(request.digest())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Digest kind, algorithm, key version, and digest are required");
        }
        requireKind(request.digestKind());
    }
    private static void requireKind(String kind) {
        if (!KINDS.contains(kind)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unsupported digest kind");
    }
    private static boolean blank(String value) { return value == null || value.isBlank(); }
    static Outcome comparison(String status, String baselineAlgorithm, String baselineKeyVersion,
                              String baselineDigest, String observedAlgorithm, String observedKeyVersion,
                              String observedDigest) {
        if (!"APPROVED".equals(status)) return Outcome.UNAPPROVED;
        if (!java.util.Objects.equals(baselineAlgorithm, observedAlgorithm)
                || !java.util.Objects.equals(baselineKeyVersion, observedKeyVersion)) {
            return Outcome.BASELINE_UNKNOWN_REAPPROVAL_REQUIRED;
        }
        return java.util.Objects.equals(baselineDigest, observedDigest)
                ? Outcome.UNCHANGED : Outcome.CHANGED_AFTER_APPROVAL;
    }
    private static Instant instant(Timestamp value) { return value == null ? null : value.toInstant(); }
    private static String sha256(String value) { try {
        return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    } catch (java.security.GeneralSecurityException error) { throw new IllegalStateException(error); } }

    private record Baseline(String algorithm, String keyVersion, String digest, String status) { }
    public enum Outcome { UNAPPROVED, UNCHANGED, CHANGED_AFTER_APPROVAL, BASELINE_UNKNOWN_REAPPROVAL_REQUIRED }
    public record Request(String digestKind, String algorithm, String keyVersion, String digest, UUID sourceRunId) { }
    public record Response(UUID artifactId, String digestKind, String algorithm, String keyVersion,
                           String approvalStatus, String approvedBy, Instant approvedAt, String revokedBy,
                           Instant revokedAt, UUID sourceRunId, Instant updatedAt) { }
}
