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

/** Approval boundary for internal definition digests and bounded control metadata. Raw definitions never enter this API. */
@Service
public class AiSecurityDigestBaselineService {
    private static final java.util.Set<String> KINDS = java.util.Set.of("PROMPT", "TOOL_DEFINITION", "GUARDRAIL_CONFIGURATION");
    private final NamedParameterJdbcTemplate jdbc;
    private final TenantSchemaExecutionService tenantExecution;
    private final TransactionTemplate transactions;
    private final AuditEventService audit;
    private final AiGridFindingService findings;

    private org.springframework.beans.factory.ObjectProvider<AiGridAssessmentWorker> assessmentWorker;
    @org.springframework.beans.factory.annotation.Autowired
    void configureAssessmentWorker(org.springframework.beans.factory.ObjectProvider<AiGridAssessmentWorker> worker) {
        this.assessmentWorker = worker;
    }

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
            jdbc.query("select pg_advisory_xact_lock(hashtextextended(cast(:tenantId as text),0))",Map.of("tenantId",tenant.getId()),rs -> null);
            assertArtifact(tenant, artifactId);
            Observation observation = currentObservation(tenant, artifactId, request.digestKind());
            if (!java.util.Objects.equals(request.sourceRunId(), observation.runId())
                    || !request.algorithm().equals(observation.algorithm())
                    || !request.keyVersion().equals(observation.keyVersion())
                    || !request.digest().equals(observation.digest())) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Approval must reference the current stored observation");
            }
            assertFresh(observation);
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
                         approval_status,approved_by,approved_at,source_run_id,approval_reference_verified)
                    values (:id,:tenantId,:artifactId,:kind,:algorithm,:keyVersion,:digest,
                            'APPROVED',:actor,now(),:sourceRunId,true)
                    on conflict (tenant_id,artifact_id,digest_kind) do update set
                        algorithm=excluded.algorithm,key_version=excluded.key_version,
                        approved_digest=excluded.approved_digest,approval_status='APPROVED',
                        approved_by=excluded.approved_by,approved_at=now(),revoked_by=null,revoked_at=null,
                        source_run_id=excluded.source_run_id,approval_reference_verified=true,updated_at=now()
                    """, params(tenant, artifactId, request, actor));
            recordHistory(tenant, artifactId, request.digestKind(), reapproval ? "REAPPROVED" : "APPROVED", actor, request.sourceRunId());
            observeCurrentTenant(tenant, artifactId, request.digestKind(), observation.algorithm(),
                    observation.keyVersion(), observation.digest(), observation.runId(), observation.observedAt());
            return required(artifactId, request.digestKind());
        }));
        audit.record(reapproval ? "ai_security.digest_baseline.reapproved" : "ai_security.digest_baseline.approved",
                "ai_security_artifact", artifactId.toString(), "{\"digestKind\":\"" + request.digestKind() + "\"}");
        return response;
    }

    public Response revoke(Tenant tenant, UUID artifactId, String digestKind, String actor) {
        requireKind(digestKind);
        Response response = tenantExecution.run(tenant, () -> transactions.execute(status -> {
            jdbc.query("select pg_advisory_xact_lock(hashtextextended(cast(:tenantId as text),0))",Map.of("tenantId",tenant.getId()),rs -> null);
            assertArtifact(tenant, artifactId);
            int changed = jdbc.update("""
                    update ai_security_artifact_digest_baselines
                       set approval_status='REVOKED',revoked_by=:actor,revoked_at=now(),updated_at=now()
                     where artifact_id=:artifactId and digest_kind=:kind and approval_status='APPROVED'
                    """, new MapSqlParameterSource().addValue("actor", actor).addValue("artifactId", artifactId)
                    .addValue("kind", digestKind));
            if (changed != 1) throw new ResponseStatusException(HttpStatus.CONFLICT, "Active digest baseline was not found");
            Observation observation = findObservation(tenant, artifactId, digestKind);
            UUID sourceRun = observation == null ? required(artifactId, digestKind).sourceRunId() : observation.runId();
            recordHistory(tenant, artifactId, digestKind, "REVOKED", actor, sourceRun);
            if (observation != null) {
                observeCurrentTenant(tenant, artifactId, digestKind, observation.algorithm(), observation.keyVersion(),
                        observation.digest(), observation.runId(), observation.observedAt());
            } else if (assessmentWorker != null) {
                assessmentWorker.getObject().enqueue(tenant,sourceRun,java.util.Set.of(
                        "GUARDRAIL_CONFIGURATION".equals(digestKind) ? "AI_GUARDRAIL_CONFIGURATION_CHANGED_AFTER_APPROVAL" : "AI_ARTIFACT_DIGEST_CHANGED_AFTER_APPROVAL"));
            }
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
        assertArtifact(tenant, artifactId);
        Instant latest = jdbc.query("select observed_at from ai_security_artifact_digest_observations where artifact_id=:artifactId and digest_kind=:kind",
                Map.of("artifactId", artifactId, "kind", digestKind), rs -> rs.next() ? rs.getTimestamp(1).toInstant() : null);
        if (latest != null && latest.isAfter(observedAt)) return null;
        Baseline baseline = jdbc.query("""
                select algorithm,key_version,approved_digest,approval_status,approval_reference_verified
                  from ai_security_artifact_digest_baselines
                 where artifact_id=:artifactId and digest_kind=:kind
                """, Map.of("artifactId", artifactId, "kind", digestKind),
                rs -> rs.next() ? new Baseline(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4), rs.getBoolean(5)) : null);
        Outcome outcome = comparison(baseline == null ? null : baseline.status(),
                baseline == null ? null : baseline.algorithm(), baseline == null ? null : baseline.keyVersion(),
                baseline == null ? null : baseline.digest(), algorithm, keyVersion, digest);

        if (baseline != null && "APPROVED".equals(baseline.status()) && !baseline.referenceVerified()) {
            outcome = Outcome.BASELINE_UNKNOWN_REAPPROVAL_REQUIRED;
        }
        if ("GUARDRAIL_CONFIGURATION".equals(digestKind) && outcome != Outcome.UNAPPROVED
                && outcome != Outcome.BASELINE_UNKNOWN_REAPPROVAL_REQUIRED) {
            outcome = AiGuardrailBaselineComparison.compare(baseline.digest(), digest);
        }
        if (observedAt.isBefore(Instant.now().minusSeconds(86400))) outcome = Outcome.CONFIGURATION_UNKNOWN;
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
        if (outcome != Outcome.UNCHANGED) {
            upsertSetupAction(tenant, artifactId, digestKind, sourceRunId, outcome);
        } else if (outcome == Outcome.UNCHANGED) {
            resolveSetupActions(artifactId, digestKind);
        }
        if (assessmentWorker != null) assessmentWorker.getObject().enqueue(tenant,sourceRunId,java.util.Set.of(
                "GUARDRAIL_CONFIGURATION".equals(digestKind) ? "AI_GUARDRAIL_CONFIGURATION_CHANGED_AFTER_APPROVAL" : "AI_ARTIFACT_DIGEST_CHANGED_AFTER_APPROVAL"));
        return outcome;
    }

    /** Recompute from the latest compatible observation and the current approval inside an isolated write. */
    public int reconcileLatest(Tenant tenant,String policyId) {
        boolean guardrailPolicy="AI_GUARDRAIL_CONFIGURATION_CHANGED_AFTER_APPROVAL".equals(policyId);
        List<Map<String,Object>> observations=jdbc.queryForList("""
                select artifact_id,digest_kind,algorithm,key_version,observed_digest,source_run_id,observed_at
                  from ai_security_artifact_digest_observations
                 where (:guardrail and digest_kind='GUARDRAIL_CONFIGURATION')
                    or (not :guardrail and digest_kind<>'GUARDRAIL_CONFIGURATION')
                 order by artifact_id,digest_kind
                """,Map.of("guardrail",guardrailPolicy));
        int compatible=0;
        for (Map<String,Object> row:observations) {
            UUID artifactId=(UUID)row.get("artifact_id");
            String kind=(String)row.get("digest_kind");
            Observation observation=findObservation(tenant,artifactId,kind);
            if (observation==null) continue;
            compatible++;
            Outcome outcome=latestOutcome(artifactId,kind,observation);
            reconcileComparison(tenant,artifactId,kind,outcome,observation.runId(),observation.observedAt());
        }
        List<Map<String,Object>> withdrawn=jdbc.queryForList("""
                select b.artifact_id,b.digest_kind,b.source_run_id from ai_security_artifact_digest_baselines b
                 where b.approval_status<>'APPROVED'
                   and ((:guardrail and b.digest_kind='GUARDRAIL_CONFIGURATION') or (not :guardrail and b.digest_kind<>'GUARDRAIL_CONFIGURATION'))
                   and not exists (select 1 from ai_security_artifact_digest_observations o where o.artifact_id=b.artifact_id and o.digest_kind=b.digest_kind)
                """,Map.of("guardrail",guardrailPolicy));
        for (var row:withdrawn) findings.withdrawBaselineComparison(tenant,new AiGridFindingService.AssessmentResult(
                UUID.randomUUID(),(UUID)row.get("source_run_id"),policyId,"1.0.0","Approval withdrawn","HIGH","DISABLED",
                "UNKNOWN","UNAPPROVED",(UUID)row.get("artifact_id"),sha256(policyId+"|"+row.get("artifact_id")+"|"+row.get("digest_kind")),Map.of("digestKind",row.get("digest_kind"))));

        return compatible+withdrawn.size();
    }

    private Outcome latestOutcome(UUID artifactId,String kind,Observation observation) {
        Baseline baseline=jdbc.query("select algorithm,key_version,approved_digest,approval_status,approval_reference_verified "
                + "from ai_security_artifact_digest_baselines where artifact_id=:id and digest_kind=:kind",
                Map.of("id",artifactId,"kind",kind),rs -> rs.next() ? new Baseline(rs.getString(1),rs.getString(2),rs.getString(3),rs.getString(4),rs.getBoolean(5)) : null);
        Outcome outcome=comparison(baseline==null ? null : baseline.status(),baseline==null ? null : baseline.algorithm(),
                baseline==null ? null : baseline.keyVersion(),baseline==null ? null : baseline.digest(),
                observation.algorithm(),observation.keyVersion(),observation.digest());
        if (baseline!=null && "APPROVED".equals(baseline.status()) && !baseline.referenceVerified()) outcome=Outcome.BASELINE_UNKNOWN_REAPPROVAL_REQUIRED;
        if ("GUARDRAIL_CONFIGURATION".equals(kind) && baseline!=null && "APPROVED".equals(baseline.status()) && baseline.referenceVerified()
                && outcome!=Outcome.BASELINE_UNKNOWN_REAPPROVAL_REQUIRED && outcome!=Outcome.CONFIGURATION_UNKNOWN)
            outcome=AiGuardrailBaselineComparison.compare(baseline.digest(),observation.digest());
        if (observation.observedAt().isBefore(Instant.now().minusSeconds(86400))) outcome=Outcome.CONFIGURATION_UNKNOWN;
        return outcome;
    }

    private void reconcileComparison(Tenant tenant,UUID artifactId,String digestKind,Outcome outcome,UUID sourceRunId,Instant observedAt) {
        boolean guardrail = "GUARDRAIL_CONFIGURATION".equals(digestKind);
        boolean changed = outcome == Outcome.CHANGED_AFTER_APPROVAL || outcome == Outcome.CONTROL_WEAKENED
                || outcome == Outcome.CONTROL_CONFIGURATION_CHANGED_REVIEW_REQUIRED;
        String policyId = guardrail ? "AI_GUARDRAIL_CONFIGURATION_CHANGED_AFTER_APPROVAL" : "AI_ARTIFACT_DIGEST_CHANGED_AFTER_APPROVAL";
        String fingerprint = sha256(policyId + "|" + artifactId + "|" + digestKind);
        // Withdrawal/incompatibility removes the basis for an existing drift finding. It is
        // still a setup/uncertainty state; this lifecycle reconciliation is not a policy pass.
        String selection = workflowSelection(tenant, policyId, guardrail);
        UUID assessmentId = persistComparison(tenant, artifactId, digestKind, outcome, sourceRunId, observedAt, policyId, selection, fingerprint);
        var assessment = new AiGridFindingService.AssessmentResult(assessmentId, sourceRunId,
                policyId, "1.0.0", guardrail ? "Approved control configuration changed; review required" : "Approved AI definition changed",
                guardrail && outcome != Outcome.CONTROL_WEAKENED ? "MEDIUM" : "HIGH", selection,
                changed ? "FAIL" : outcome == Outcome.UNCHANGED ? "PASS" : "UNKNOWN", outcome.name(), artifactId, fingerprint,
                Map.of("digestKind", digestKind, "comparisonOutcome", outcome.name(), "changedAfterApproval", changed));
        boolean findingChanged = changed || outcome == Outcome.UNCHANGED ? findings.reconcile(tenant, assessment)
                : findings.withdrawBaselineComparison(tenant, assessment);
        if (findingChanged) findings.refreshProjectionAfterCommit(tenant);
    }

    private UUID persistComparison(Tenant tenant, UUID artifactId, String kind, Outcome outcome, UUID runId,
                                   Instant observedAt, String policyId, String selection, String fingerprint) {
        boolean known = outcome == Outcome.UNCHANGED || outcome == Outcome.CHANGED_AFTER_APPROVAL
                || outcome == Outcome.CONTROL_WEAKENED || outcome == Outcome.CONTROL_CONFIGURATION_CHANGED_REVIEW_REQUIRED;
        String decision = outcome == Outcome.UNCHANGED ? "PASS" : known ? "FAIL" : "NO_DECISION";
        String factKey = "GUARDRAIL_CONFIGURATION".equals(kind) ? "guardrail.baseline_comparison_outcome" : "artifact.digest_comparison_outcome";
        var evidence = com.fasterxml.jackson.databind.node.JsonNodeFactory.instance.objectNode();
        evidence.putObject(factKey).put("value", outcome.name()).put("state", known ? "KNOWN" : "UNKNOWN")
                .put("evidenceClass", "CONFIGURATION").put("observedAt", observedAt.toString());
        evidence.put("digestKind", kind);
        return jdbc.queryForObject("""
                insert into ai_grid_assessments (id,tenant_id,run_id,policy_id,policy_version,subject_type,subject_id,
                    selection,applicability,evidence_readiness,decision,reason_code,input_facts_json,fingerprint,evaluation_as_of,decision_fingerprint)
                values (:id,:tenantId,:runId,:policyId,'1.0.0','ARTIFACT',:artifactId,:selection,'APPLICABLE',:readiness,
                    :decision,:reason,cast(:evidence as jsonb),:fingerprint,:asOf,:decisionFingerprint)
                on conflict (tenant_id,run_id,policy_id,subject_type,subject_id,fingerprint) do update set
                    selection=excluded.selection,evidence_readiness=excluded.evidence_readiness,decision=excluded.decision,
                    reason_code=excluded.reason_code,input_facts_json=excluded.input_facts_json,
                    evaluation_as_of=excluded.evaluation_as_of,decision_fingerprint=excluded.decision_fingerprint,evaluated_at=now()
                returning id
                """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                .addValue("runId", runId).addValue("policyId", policyId).addValue("artifactId", artifactId)
                .addValue("selection", selection).addValue("readiness", known ? "READY" : "INCOMPLETE")
                .addValue("decision", decision).addValue("reason", outcome.name()).addValue("evidence", evidence.toString())
                .addValue("fingerprint", fingerprint).addValue("asOf", Timestamp.from(Instant.now()))
                .addValue("decisionFingerprint", sha256(kind + "|" + outcome + "|" + runId + "|" + observedAt)), UUID.class);
    }

    private String workflowSelection(Tenant tenant, String policyId, boolean guardrail) {
        List<String> selected = jdbc.query("select selection from ai_grid_policy_selections where policy_id=:policyId and configuration_source='TENANT_OVERRIDE'",
                Map.of("policyId", policyId), (rs, row) -> rs.getString(1));
        if (!guardrail) {
            List<String> defaults=jdbc.query("select resolved_default_selection from " + AiGridPolicyResolution.versions(":tenantId") + " p where policy_id=:policyId",
                    Map.of("tenantId",tenant.getId(),"policyId",policyId),(rs,row) -> rs.getString(1));
            return selected.isEmpty() ? defaults.isEmpty() ? "ENABLED" : defaults.get(0) : selected.get(0);
        }
        // New control-regression findings must pass the existing distribution/canary boundary.
        List<String> distributed = jdbc.query("""
                select d.default_selection from platform.ai_grid_policy_distribution d
                 join platform.ai_grid_policy_versions p on p.policy_id=d.policy_id and p.version=d.pinned_version
                where d.policy_id=:policyId and p.version='1.0.0'
                  and d.approved_package_digest=p.package_digest
                  and exists (select 1 from platform.ai_grid_policy_release_decisions r
                      where r.id=d.release_decision_id and r.policy_id=p.policy_id and r.policy_version=p.version
                        and r.package_digest=p.package_digest and r.decision='APPROVED')
                  and p.lifecycle in ('APPROVED','PUBLISHED','CANARY')
                  and platform.ai_grid_policy_visible_to_tenant(d.available,d.rollout_stage,d.canary_tenant_ids_json,cast(:tenantId as uuid))
                """, Map.of("policyId", policyId, "tenantId", tenant.getId().toString()), (rs, row) -> rs.getString(1));
        if (distributed.isEmpty()) return "DISABLED";
        return selected.isEmpty() ? distributed.get(0) : selected.get(0);
    }

    public Response approveObservation(Tenant tenant, UUID artifactId, ObservationRequest request, String actor, boolean reapproval) {
        if (request == null || request.sourceRunId() == null || request.observedAt() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Observation reference is required");
        }
        requireKind(request.digestKind());
        return tenantExecution.run(tenant, () -> transactions.execute(status -> {
            jdbc.query("select pg_advisory_xact_lock(hashtextextended(cast(:tenantId as text),0))",Map.of("tenantId",tenant.getId()),rs -> null);
            assertArtifact(tenant, artifactId);
            Observation current = currentObservation(tenant, artifactId, request.digestKind());
            if (!current.runId().equals(request.sourceRunId()) || !current.observedAt().equals(request.observedAt())) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Observation changed; reload before approving");
            }
            return approve(tenant, artifactId, new Request(request.digestKind(), current.algorithm(), current.keyVersion(),
                    current.digest(), current.runId()), actor, reapproval);
        }));
    }

    public List<ObservationResponse> observations(Tenant tenant, UUID artifactId) {
        return tenantExecution.run(tenant, () -> jdbc.query("""
                select o.digest_kind,o.comparison_outcome,o.source_run_id,o.observed_at,o.observed_digest,b.approved_digest,
                       (select coalesce(body.content_json->'attributes'->>'version',body.content_json->'attributes'->>'modelVersion',
                                        body.content_json->'attributes'->>'guardrailVersion')
                          from ai_grid_snapshot_manifests m join ai_grid_snapshot_bodies body on body.id=m.body_id
                         where m.tenant_id=o.tenant_id and m.artifact_id=o.artifact_id and m.run_id=o.source_run_id
                           and m.observed_at=o.observed_at order by m.id desc limit 1) observation_version
                  from ai_security_artifact_digest_observations o
                  left join ai_security_artifact_digest_baselines b
                    on b.tenant_id=o.tenant_id and b.artifact_id=o.artifact_id and b.digest_kind=o.digest_kind
                 where o.tenant_id=:tenantId and o.artifact_id=:artifactId order by o.digest_kind
                """, Map.of("tenantId", tenant.getId(), "artifactId", artifactId), (rs, row) ->
                new ObservationResponse(rs.getString(1), rs.getString(2), rs.getObject(3, UUID.class),
                        rs.getTimestamp(4).toInstant(), rs.getTimestamp(4).toInstant().isBefore(Instant.now().minusSeconds(86400)),
                        "GUARDRAIL_CONFIGURATION".equals(rs.getString(1))
                                ? AiGuardrailBaselineComparison.changedFields(rs.getString(6), rs.getString(5)) : List.of(), rs.getString(7))));
    }

    public List<HistoryResponse> history(Tenant tenant, UUID artifactId) {
        return tenantExecution.run(tenant, () -> jdbc.query("""
                select id,digest_kind,action,actor,source_run_id,recorded_at from ai_security_baseline_history
                 where tenant_id=:tenantId and artifact_id=:artifactId order by recorded_at desc,id
                """, Map.of("tenantId", tenant.getId(), "artifactId", artifactId), (rs, row) ->
                new HistoryResponse(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3), rs.getString(4),
                        rs.getObject(5, UUID.class), rs.getTimestamp(6).toInstant())));
    }

    private Observation currentObservation(Tenant tenant, UUID artifactId, String kind) {
        Observation observation = findObservation(tenant, artifactId, kind);
        if (observation == null) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Tenant-owned observation and source run were not found");
        return observation;
    }

    private Observation findObservation(Tenant tenant, UUID artifactId, String kind) {
        return jdbc.query("""
                select algorithm,key_version,observed_digest,source_run_id,observed_at
                  from ai_security_artifact_digest_observations o
                 where o.tenant_id=:tenantId and o.artifact_id=:artifactId and o.digest_kind=:kind
                   and exists (select 1 from ai_security_observation_receipts r
                               where r.tenant_id=o.tenant_id and r.run_id=o.source_run_id)
                """, Map.of("tenantId", tenant.getId(), "artifactId", artifactId, "kind", kind), rs -> {
            if (!rs.next()) return null;
            return new Observation(rs.getString(1), rs.getString(2), rs.getString(3), rs.getObject(4, UUID.class), rs.getTimestamp(5).toInstant());
        });
    }

    private static void assertFresh(Observation observation) {
        if (observation.observedAt().isBefore(Instant.now().minusSeconds(86400))
                || observation.observedAt().isAfter(Instant.now().plusSeconds(300))) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "A fresh observation is required for approval");
        }
    }

    private void recordHistory(Tenant tenant, UUID artifactId, String kind, String action, String actor, UUID runId) {
        jdbc.update("""
                insert into ai_security_baseline_history
                    (id,tenant_id,artifact_id,digest_kind,action,actor,source_run_id,algorithm,key_version,approved_value,approval_reference_verified)
                select :id,:tenantId,:artifactId,:kind,:action,:actor,:runId,algorithm,key_version,approved_digest,approval_reference_verified
                  from ai_security_artifact_digest_baselines where artifact_id=:artifactId and digest_kind=:kind
                """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                .addValue("artifactId", artifactId).addValue("kind", kind).addValue("action", action)
                .addValue("actor", actor).addValue("runId", runId));
    }

    private void upsertSetupAction(Tenant tenant, UUID artifactId, String kind, UUID runId, Outcome outcome) {
        String fingerprint = sha256("digest-baseline|" + artifactId + "|" + kind);
        jdbc.update("""
                insert into ai_grid_setup_actions
                    (id,tenant_id,run_id,artifact_id,fingerprint,priority,category,action_code,title,detail,evidence_key)
                values (:id,:tenantId,:runId,:artifactId,:fingerprint,90,'DIGEST_APPROVAL','REAPPROVE_DIGEST_BASELINE',
                        :title,'Review the current observation and approve a compatible baseline.',:evidenceKey)
                on conflict (tenant_id,fingerprint) do update set
                    run_id=excluded.run_id,status='OPEN',last_observed_at=now(),resolved_at=null,
                    detail=excluded.detail,title=excluded.title,evidence_key=excluded.evidence_key
                """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                .addValue("runId", runId).addValue("artifactId", artifactId).addValue("fingerprint", fingerprint)
                .addValue("title", outcome == Outcome.UNAPPROVED ? "Approve current observation" : "Review baseline comparison")
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
        List<UUID> ids = jdbc.query("select id from ai_security_artifacts where id=:id and tenant_id=:tenantId for update",
                Map.of("id", artifactId, "tenantId", tenant.getId()), (rs, row) -> rs.getObject(1, UUID.class));
        if (ids.size() != 1) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "AI artifact was not found");
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
        if (kind == null || !KINDS.contains(kind)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unsupported digest kind");
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

    private record Observation(String algorithm, String keyVersion, String digest, UUID runId, Instant observedAt) { }
    public record ObservationRequest(String digestKind, UUID sourceRunId, Instant observedAt) { }
    public record ObservationResponse(String digestKind, String comparisonOutcome, UUID sourceRunId, Instant observedAt, boolean stale, List<String> changedFields, String observationVersion) { }
    public record HistoryResponse(UUID id, String digestKind, String action, String actor, UUID sourceRunId, Instant recordedAt) { }
    private record Baseline(String algorithm, String keyVersion, String digest, String status, boolean referenceVerified) { }
    public enum Outcome { UNAPPROVED, UNCHANGED, CHANGED_AFTER_APPROVAL, BASELINE_UNKNOWN_REAPPROVAL_REQUIRED,
        CONTROL_WEAKENED, CONTROL_CONFIGURATION_CHANGED_REVIEW_REQUIRED, CONFIGURATION_UNKNOWN }
    public record Request(String digestKind, String algorithm, String keyVersion, String digest, UUID sourceRunId) { }
    public record Response(UUID artifactId, String digestKind, String algorithm, String keyVersion,
                           String approvalStatus, String approvedBy, Instant approvedAt, String revokedBy,
                           Instant revokedAt, UUID sourceRunId, Instant updatedAt) { }
}
