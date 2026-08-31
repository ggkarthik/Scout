package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/** Platform-computed R2 certification gates plus separately approved template precision evidence. */
@Service
public class AiGridR2CertificationService {
    public static final String RELEASE_ID = "R2";
    private final NamedParameterJdbcTemplate jdbc;
    private final TransactionTemplate transactions;
    private final ObjectMapper objectMapper;
    private final TenantRepository tenants;
    private final TenantSchemaExecutionService tenantExecution;
    private final AiGridValidationGovernanceService governance;

    public AiGridR2CertificationService(NamedParameterJdbcTemplate jdbc, TransactionTemplate transactions,
                                        ObjectMapper objectMapper, TenantRepository tenants,
                                        TenantSchemaExecutionService tenantExecution,
                                        AiGridValidationGovernanceService governance) {
        this.jdbc = jdbc;
        this.transactions = transactions;
        this.objectMapper = objectMapper;
        this.tenants = tenants;
        this.tenantExecution = tenantExecution;
        this.governance = governance;
    }

    public Readiness readiness() {
        return TenantContext.runAsPlatform(() -> {
            List<Gate> gates = List.of(precisionGate(), explainabilityGate(), ownerRoutingGate(),
                    staleEvidenceGate(), closureGate());
            boolean ready = gates.stream().allMatch(g -> "PASS".equals(g.status()));
            return new Readiness(RELEASE_ID, ready, gates);
        });
    }

    public AiGridValidationGovernanceService.PrecisionReview createPrecisionReview(
            PrecisionReviewCommand command, String actor) {
        if (command.minimumSampleSize() < 30)
            throw new IllegalArgumentException("R2 precision reviews require at least 30 positive samples");
        if (command.labelSetVersion() == null || command.labelSetVersion().isBlank() || command.answerKeyRunId() == null)
            throw new IllegalArgumentException("R2 precision reviews require label-set and answer-key bindings");
        return TenantContext.runAsPlatform(() -> transactions.execute(status -> {
            Correlation correlation = correlation(command.correlationId(), command.correlationVersion());
            Integer answerKey = jdbc.queryForObject("""
                    select count(*) from platform.ai_grid_answer_key_runs
                     where id=:id and status='PASS' and provenance_state='PLATFORM_RUN_BOUND'
                       and total_cases=matched_cases
                    """, Map.of("id", command.answerKeyRunId()), Integer.class);
            if (answerKey == null || answerKey != 1)
                throw new IllegalArgumentException("R2 precision requires a passing platform-run-bound answer key");
            UUID id = UUID.randomUUID();
            jdbc.update("""
                    insert into platform.ai_grid_precision_reviews
                        (id,policy_id,policy_version,population_definition,sampling_method,minimum_sample_size,
                         confidence_level,precision_threshold,material_change_digest,created_by,
                         label_set_version,answer_key_run_id)
                    values (:id,:correlationId,:version,:population,:sampling,:minimum,:confidence,:threshold,
                            :digest,:actor,:labelSet,:answerKey)
                    on conflict (policy_id,policy_version,material_change_digest) do nothing
                    """, new MapSqlParameterSource().addValue("id", id).addValue("correlationId", correlation.id())
                    .addValue("version", correlation.version()).addValue("population", command.populationDefinition())
                    .addValue("sampling", command.samplingMethod()).addValue("minimum", command.minimumSampleSize())
                    .addValue("confidence", command.confidenceLevel() == null ? 0.95 : command.confidenceLevel())
                    .addValue("threshold", correlation.threshold()).addValue("digest", digest(correlation))
                    .addValue("actor", actor).addValue("labelSet", command.labelSetVersion())
                    .addValue("answerKey", command.answerKeyRunId()));
            UUID reviewId = jdbc.queryForObject("""
                    select id from platform.ai_grid_precision_reviews
                     where policy_id=:id and policy_version=:version and material_change_digest=:digest
                    """, new MapSqlParameterSource().addValue("id", correlation.id())
                    .addValue("version", correlation.version()).addValue("digest", digest(correlation)), UUID.class);
            return governance.precisionReview(reviewId);
        }));
    }

    public Decision decide(String actor) {
        Readiness readiness = readiness();
        return TenantContext.runAsPlatform(() -> transactions.execute(status -> {
            UUID id = UUID.randomUUID();
            String decision = readiness.ready() ? "APPROVED" : "BLOCKED";
            String reason = readiness.ready() ? "All R2 release gates passed" : "Blocked by "
                    + readiness.gates().stream().filter(g -> !"PASS".equals(g.status())).map(Gate::code).toList();
            jdbc.update("""
                    insert into platform.ai_grid_release_decisions
                        (id,release_id,decision,gate_snapshot_json,reason,decided_by)
                    values (:id,'R2',:decision,cast(:snapshot as jsonb),:reason,:actor)
                    """, new MapSqlParameterSource().addValue("id", id).addValue("decision", decision)
                    .addValue("snapshot", json(readiness.gates())).addValue("reason", reason).addValue("actor", actor));
            return new Decision(id, decision, reason, readiness.gates());
        }));
    }

    private Gate precisionGate() {
        List<Correlation> correlations = correlations();
        List<String> blocked = new ArrayList<>();
        for (Correlation correlation : correlations) {
            Integer passing = jdbc.queryForObject("""
                    select count(*) from platform.ai_grid_precision_reviews
                     where policy_id=:id and policy_version=:version and material_change_digest=:digest
                       and status='PASSED' and bias_status='PASSED'
                       and resolved_positive_samples>=minimum_sample_size
                       and confidence_lower>=:threshold
                       and answer_key_run_id is not null and label_set_version<>'R1-LEGACY'
                       and not exists (select 1 from platform.ai_grid_precision_samples s
                           join platform.ai_grid_precision_labels l on l.sample_id=s.id
                          where s.review_id=ai_grid_precision_reviews.id
                            and l.label_version<>ai_grid_precision_reviews.label_set_version)
                    """, new MapSqlParameterSource().addValue("id", correlation.id()).addValue("version", correlation.version())
                    .addValue("digest", digest(correlation)).addValue("threshold", correlation.threshold()), Integer.class);
            if (passing == null || passing == 0) blocked.add(correlation.id() + "@" + correlation.version());
        }
        Integer manifestCount = jdbc.queryForObject("""
                select count(*) from platform.ai_grid_release_manifest_items
                 where release_id='R2' and subject_type='CORRELATION'
                """, Map.of(), Integer.class);
        if (manifestCount == null || manifestCount != 3 || correlations.size() < 3) return new Gate("TEMPLATE_PRECISION", "BLOCKED",
                "R2 requires its immutable three-correlation release manifest");
        return blocked.isEmpty() ? new Gate("TEMPLATE_PRECISION", "PASS", "All three templates passed approved thresholds")
                : new Gate("TEMPLATE_PRECISION", "BLOCKED", "Missing current precision approval: " + blocked);
    }

    private Gate explainabilityGate() {
        long total = 0, incomplete = 0;
        for (Tenant tenant : measurableTenants()) {
            long[] counts = tenantExecution.run(tenant, () -> jdbc.queryForObject("""
                    select count(*) total, count(*) filter (where p.impact='' or p.root_cause='' or p.breakpoint=''
                        or p.confidence_method='' or not exists (select 1 from ai_grid_exposure_observations o
                          where o.exposure_path_id=p.id and o.coverage_epoch_id=p.last_complete_epoch_id
                            and o.observed_at=(select max(x.observed_at) from ai_grid_exposure_observations x
                                               where x.exposure_path_id=p.id and x.coverage_epoch_id=p.last_complete_epoch_id)
                            and o.system_id is not null and jsonb_array_length(o.path_json)>1
                            and jsonb_array_length(coalesce(o.evidence_json -> 'factIds','[]'::jsonb))>0
                            and o.temporal_valid_from is not null and o.correlation_material_digest is not null)) incomplete
                      from ai_grid_exposure_paths p
                    """, Map.of(), (rs, n) -> new long[]{rs.getLong(1), rs.getLong(2)}));
            total += counts[0]; incomplete += counts[1];
        }
        if (total == 0) return new Gate("EXPLAINABILITY", "BLOCKED", "No R2 exposure evidence exists");
        return incomplete == 0 ? new Gate("EXPLAINABILITY", "PASS", "Every exposure has path, system, evidence, validity, impact, root cause, and breakpoint")
                : new Gate("EXPLAINABILITY", "FAIL", incomplete + " exposures have incomplete explanations");
    }

    private Gate ownerRoutingGate() {
        long accepted = 0, routed = 0;
        for (Tenant tenant : measurableTenants()) {
            long[] counts = tenantExecution.run(tenant, () -> jdbc.queryForObject("""
                    with accepted as (
                        select distinct on (d.exposure_path_id) d.exposure_path_id,d.disposition
                          from ai_grid_exposure_dispositions d order by d.exposure_path_id,d.created_at desc
                    )
                    select count(*) filter (where a.disposition='ACCEPTED' and p.severity in ('HIGH','CRITICAL')),
                           count(*) filter (where a.disposition='ACCEPTED' and p.severity in ('HIGH','CRITICAL')
                               and f.owner_group is not null and f.due_at is not null and exists (
                                   select 1 from ai_grid_exposure_associations ea
                                   join ai_grid_systems s on s.id=ea.system_id
                                   join ai_grid_system_revisions sr on sr.system_id=s.id and sr.revision=s.current_revision
                                   join ai_grid_system_memberships sm on sm.system_revision_id=sr.id
                                   join ai_security_artifacts owned on owned.id=sm.artifact_id
                                    where ea.exposure_path_id=p.id and ea.association_role='AFFECTED_SYSTEM'
                                      and owned.owner_state='CONFIRMED' and owned.owner_name=f.owner_group))
                      from accepted a join ai_grid_exposure_paths p on p.id=a.exposure_path_id
                      left join findings f on f.id=p.finding_id
                    """, Map.of(), (rs, n) -> new long[]{rs.getLong(1), rs.getLong(2)}));
            accepted += counts[0]; routed += counts[1];
        }
        if (accepted == 0) return new Gate("OWNER_AND_SLA_ROUTING", "BLOCKED", "No accepted high-priority exposures are available");
        double ratio = (double) routed / accepted;
        return ratio >= 0.90 ? new Gate("OWNER_AND_SLA_ROUTING", "PASS", routed + "/" + accepted + " accepted exposures are owner/SLA routed")
                : new Gate("OWNER_AND_SLA_ROUTING", "FAIL", routed + "/" + accepted + " is below the 90% requirement");
    }

    private Gate staleEvidenceGate() {
        long stale = 0, demoted = 0;
        for (Tenant tenant : measurableTenants()) {
            long[] counts = tenantExecution.run(tenant, () -> jdbc.queryForObject("""
                select count(*) filter (where p.state='VALIDATED_EXPOSURE' and exists (
                    select 1 from ai_grid_exposure_observations o where o.exposure_path_id=p.id
                      and o.coverage_epoch_id=p.last_complete_epoch_id
                      and o.temporal_valid_until is not null and o.temporal_valid_until<now())),
                       count(*) filter (where p.state='EXPOSURE_HYPOTHESIS' and p.validated_at is not null)
                  from ai_grid_exposure_paths p
                """, Map.of(), (rs, n) -> new long[]{rs.getLong(1), rs.getLong(2)}));
            stale += counts[0]; demoted += counts[1];
        }
        if (demoted == 0) return new Gate("STALE_EVIDENCE_DEMOTION", "BLOCKED",
                "No representative stale-evidence demotion cohort exists");
        return stale == 0 ? new Gate("STALE_EVIDENCE_DEMOTION", "PASS", "No stale path remains validated")
                : new Gate("STALE_EVIDENCE_DEMOTION", "FAIL", stale + " stale paths remain validated");
    }

    private Gate closureGate() {
        long invalid = 0, closed = 0;
        for (Tenant tenant : measurableTenants()) {
            long[] counts = tenantExecution.run(tenant, () -> jdbc.queryForObject("""
                select count(*) filter (where p.status='CLOSED'),
                       count(*) filter (where p.status='CLOSED' and not exists (
                    select 1 from ai_grid_exposure_observations o
                     where o.exposure_path_id=p.id and o.run_id=p.last_complete_run_id
                       and o.coverage_epoch_id=p.last_complete_epoch_id and o.state='ABSENT'
                       and exists (select 1 from ai_grid_exposure_executions e
                            where e.coverage_epoch_id=o.coverage_epoch_id
                              and e.material_digest=o.correlation_material_digest)))
                  from ai_grid_exposure_paths p
                """, Map.of(), (rs, n) -> new long[]{rs.getLong(1), rs.getLong(2)}));
            closed += counts[0]; invalid += counts[1];
        }
        if (closed == 0) return new Gate("COMPLETE_REASSESSMENT_CLOSURE", "BLOCKED",
                "No representative complete-reassessment closure cohort exists");
        return invalid == 0 ? new Gate("COMPLETE_REASSESSMENT_CLOSURE", "PASS", "Every closure is backed by a complete-run absence observation")
                : new Gate("COMPLETE_REASSESSMENT_CLOSURE", "FAIL", invalid + " closures lack complete reassessment proof");
    }

    private List<Tenant> measurableTenants() {
        List<UUID> ids = jdbc.query("select tenant_id from platform.tenant_schema_versions where status='CURRENT' and current_version>=56",
                (rs, n) -> rs.getObject(1, UUID.class));
        return ids.stream().map(tenants::findById).flatMap(java.util.Optional::stream).toList();
    }
    private List<Correlation> correlations() {
        return jdbc.query("""
                select c.correlation_id,c.version,c.precision_threshold,c.requirements_json::text,
                       allowed_node_types_json::text,allowed_edge_types_json::text,max_path_depth,max_fan_out
                  from platform.ai_grid_release_manifest_items m
                  join platform.ai_grid_correlation_versions c on c.correlation_id=m.subject_id
                       and c.version=m.subject_version
                 where m.release_id='R2' and m.subject_type='CORRELATION' and c.lifecycle='PUBLISHED'
                 order by c.correlation_id
                """, (rs, n) -> new Correlation(rs.getString(1), rs.getString(2), rs.getDouble(3),
                rs.getString(4), rs.getString(5), rs.getString(6), rs.getInt(7), rs.getInt(8)));
    }
    private Correlation correlation(String id, String version) {
        return correlations().stream().filter(c -> c.id().equals(id) && c.version().equals(version)).findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Published correlation version not found"));
    }
    private String digest(Correlation c) {
        String material = c.id() + '|' + c.version() + '|' + c.requirements() + '|' + c.nodes() + '|' + c.edges()
                + '|' + c.depth() + '|' + c.fanOut() + '|' + classDigest();
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(material.getBytes(StandardCharsets.UTF_8))); }
        catch (Exception e) { throw new IllegalStateException("Unable to digest R2 correlation", e); }
    }
    private String classDigest() {
        try (var input = AiGridExposureService.class.getResourceAsStream("AiGridExposureService.class")) {
            if (input == null) throw new IllegalStateException("R2 engine build material unavailable");
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(input.readAllBytes());
            for (Class<?> dependent : List.of(AiGridSystemService.class, AiGridHostContextService.class,
                    AiGridExposureFindingService.class)) {
                try (var dependency = dependent.getResourceAsStream(dependent.getSimpleName() + ".class")) {
                    if (dependency == null) throw new IllegalStateException("R2 dependent build material unavailable");
                    digest.update(dependency.readAllBytes());
                }
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (Exception e) { throw new IllegalStateException("Unable to digest R2 engine", e); }
    }
    private String json(Object value) {
        try { return objectMapper.writeValueAsString(value); }
        catch (Exception e) { throw new IllegalArgumentException("Unable to serialize R2 gate snapshot", e); }
    }

    private record Correlation(String id, String version, double threshold, String requirements,
                               String nodes, String edges, int depth, int fanOut) {}
    public record Gate(String code, String status, String rationale) {}
    public record Readiness(String releaseId, boolean ready, List<Gate> gates) {}
    public record PrecisionReviewCommand(String correlationId, String correlationVersion,
                                         String populationDefinition, String samplingMethod,
                                         int minimumSampleSize, Double confidenceLevel,
                                         String labelSetVersion, UUID answerKeyRunId) {}
    public record Decision(UUID id, String decision, String reason, List<Gate> gates) {}
}
