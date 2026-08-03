package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
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
public class AiGridValidationGovernanceService {
    private static final List<String> LABELS = List.of(
            "TRUE_POSITIVE", "FALSE_POSITIVE", "TRUE_NEGATIVE", "FALSE_NEGATIVE", "EXCLUDE");
    private static final List<String> ANSWER_KEY_OUTPUTS = List.of(
            "inventory", "technologies", "capabilities", "facts", "relationships", "applicability",
            "decisions", "findings", "gaps", "closureTransitions");

    private final NamedParameterJdbcTemplate jdbc;
    private final TransactionTemplate transactions;
    private final ObjectMapper objectMapper;
    private final TenantSchemaExecutionService tenantExecution;

    public AiGridValidationGovernanceService(NamedParameterJdbcTemplate jdbc, TransactionTemplate transactions,
                                             ObjectMapper objectMapper,
                                             TenantSchemaExecutionService tenantExecution) {
        this.jdbc = jdbc;
        this.transactions = transactions;
        this.objectMapper = objectMapper;
        this.tenantExecution = tenantExecution;
    }

    public AnswerKeyEnvironment createEnvironment(EnvironmentCommand command, String actor) {
        requireText(command.environmentKey(), "environmentKey");
        requireText(command.version(), "version");
        requireText(command.provider(), "provider");
        requireText(command.resourceFamily(), "resourceFamily");
        requireText(command.engineeringOwner(), "engineeringOwner");
        requireText(command.securityReviewer(), "securityReviewer");
        requireText(command.changeSummary(), "changeSummary");
        if (command.engineeringOwner().equalsIgnoreCase(command.securityReviewer())) {
            throw badRequest("engineeringOwner and securityReviewer must be independent");
        }
        if (command.providerApiVersions() == null || command.providerApiVersions().isEmpty()) {
            throw badRequest("providerApiVersions are required");
        }
        if (command.expectedEconomics() == null || command.expectedEconomics().isEmpty()) {
            throw badRequest("expectedEconomics are required");
        }
        if (command.reviewDueAt() == null || !command.reviewDueAt().isAfter(Instant.now())) {
            throw badRequest("reviewDueAt must be in the future");
        }
        return TenantContext.runAsPlatform(() -> transactions.execute(status -> {
            UUID id = UUID.randomUUID();
            jdbc.update("""
                    insert into platform.ai_grid_answer_key_environments
                        (id, environment_key, version, provider, resource_family, engineering_owner,
                         security_reviewer, provider_api_versions_json, expected_economics_json,
                         change_summary, review_due_at, created_by)
                    values (:id, :key, :version, :provider, :family, :owner, :reviewer,
                            cast(:apis as jsonb), cast(:economics as jsonb), :summary, :due, :actor)
                    """, new MapSqlParameterSource()
                    .addValue("id", id).addValue("key", command.environmentKey()).addValue("version", command.version())
                    .addValue("provider", command.provider()).addValue("family", command.resourceFamily())
                    .addValue("owner", command.engineeringOwner()).addValue("reviewer", command.securityReviewer())
                    .addValue("apis", json(command.providerApiVersions())).addValue("economics", json(command.expectedEconomics()))
                    .addValue("summary", command.changeSummary())
                    .addValue("due", java.sql.Timestamp.from(command.reviewDueAt()))
                    .addValue("actor", actor));
            return environment(id);
        }));
    }

    public AnswerKeyCase addCase(UUID environmentId, CaseCommand command, String actor) {
        requireText(command.caseKey(), "caseKey");
        requireText(command.scenario(), "scenario");
        requireText(command.labelVersion(), "labelVersion");
        requireText(command.rationale(), "rationale");
        requireText(command.evidenceReference(), "evidenceReference");
        if ((command.policyId() == null) != (command.policyVersion() == null)) {
            throw badRequest("policyId and policyVersion must be supplied together");
        }
        return TenantContext.runAsPlatform(() -> transactions.execute(status -> {
            assertEnvironmentLifecycle(environmentId, "DRAFT");
            UUID id = UUID.randomUUID();
            jdbc.update("""
                    insert into platform.ai_grid_answer_key_cases
                        (id, environment_id, case_key, scenario, policy_id, policy_version,
                         expected_applicability, expected_decision, expected_finding, expected_json,
                         label_version, rationale, evidence_reference, created_by)
                    values (:id, :environmentId, :caseKey, :scenario, :policyId, :policyVersion,
                            :applicability, :decision, :finding, cast(:expected as jsonb),
                            :labelVersion, :rationale, :evidence, :actor)
                    """, new MapSqlParameterSource().addValue("id", id).addValue("environmentId", environmentId)
                    .addValue("caseKey", command.caseKey()).addValue("scenario", command.scenario())
                    .addValue("policyId", command.policyId()).addValue("policyVersion", command.policyVersion())
                    .addValue("applicability", command.expectedApplicability())
                    .addValue("decision", command.expectedDecision()).addValue("finding", command.expectedFinding())
                    .addValue("expected", json(command.expected())).addValue("labelVersion", command.labelVersion())
                    .addValue("rationale", command.rationale()).addValue("evidence", command.evidenceReference())
                    .addValue("actor", actor));
            return answerKeyCase(id);
        }));
    }

    public AnswerKeyEnvironment certifyEnvironment(UUID environmentId, String actor) {
        return TenantContext.runAsPlatform(() -> transactions.execute(status -> {
            AnswerKeyEnvironment environment = environment(environmentId);
            if (!"DRAFT".equals(environment.lifecycle())) throw conflict("Only a draft answer key can be certified");
            Map<String, Integer> scenarioCounts = jdbc.query("""
                    select scenario, count(*) count from platform.ai_grid_answer_key_cases
                     where environment_id = :id group by scenario
                    """, Map.of("id", environmentId), rs -> {
                Map<String, Integer> counts = new HashMap<>();
                while (rs.next()) counts.put(rs.getString("scenario"), rs.getInt("count"));
                return counts;
            });
            if (scenarioCounts.getOrDefault("SECURE", 0) == 0 || scenarioCounts.getOrDefault("INSECURE", 0) == 0) {
                throw conflict("Certification requires at least one SECURE and one INSECURE case");
            }
            if (scenarioCounts.getOrDefault("PROXY_VS_VERIFIED", 0) == 0) {
                throw conflict("Certification requires an explicit PROXY_VS_VERIFIED case");
            }
            java.util.Set<String> declaredOutputs = new java.util.HashSet<>();
            for (AnswerKeyCase answerCase : cases(environmentId)) {
                parse(answerCase.expectedJson()).fieldNames().forEachRemaining(declaredOutputs::add);
            }
            List<String> missingOutputs = ANSWER_KEY_OUTPUTS.stream()
                    .filter(output -> !declaredOutputs.contains(output)).toList();
            if (!missingOutputs.isEmpty()) {
                throw conflict("Answer key is missing expected output categories: " + String.join(", ", missingOutputs));
            }
            jdbc.update("""
                    update platform.ai_grid_answer_key_environments set lifecycle = 'RETIRED'
                     where environment_key = :key and lifecycle = 'CERTIFIED' and id <> :id
                    """, Map.of("key", environment.environmentKey(), "id", environmentId));
            jdbc.update("""
                    update platform.ai_grid_answer_key_environments
                       set lifecycle = 'CERTIFIED', certified_at = now()
                     where id = :id
                    """, Map.of("id", environmentId));
            return environment(environmentId);
        }));
    }

    public AnswerKeyRun recordRun(UUID environmentId, RunCommand command, String actor) {
        requireText(command.catalogDigest(), "catalogDigest");
        if (command.sourceTenantId() == null) throw badRequest("sourceTenantId is required");
        if (command.sourceRunId() == null) throw badRequest("sourceRunId is required");
        if (command.results() == null || command.results().isEmpty()) throw badRequest("results are required");
        List<AnswerKeyCase> declaredCases = cases(environmentId);
        RunProvenance provenance = validateRunProvenance(command, declaredCases);
        return TenantContext.runAsPlatform(() -> transactions.execute(status -> {
            AnswerKeyEnvironment environment = environment(environmentId);
            if (!"CERTIFIED".equals(environment.lifecycle()) || !environment.reviewDueAt().isAfter(Instant.now())) {
                throw conflict("Answer key is not currently certified and fresh");
            }
            List<AnswerKeyCase> cases = cases(environmentId);
            Map<String, ResultCommand> supplied = new HashMap<>();
            for (ResultCommand result : command.results()) {
                if (supplied.put(result.caseKey(), result) != null) throw badRequest("Duplicate result: " + result.caseKey());
            }
            if (supplied.size() != cases.size() || cases.stream().anyMatch(c -> !supplied.containsKey(c.caseKey()))) {
                throw conflict("Run must report exactly one result for every answer-key case");
            }
            UUID runId = UUID.randomUUID();
            int matched = 0;
            List<ResultInsert> resultRows = new ArrayList<>();
            for (AnswerKeyCase answerCase : cases) {
                ResultCommand result = supplied.get(answerCase.caseKey());
                boolean matches = parse(answerCase.expectedJson()).equals(objectMapper.valueToTree(result.observed()));
                if (matches) matched++;
                resultRows.add(new ResultInsert(answerCase.id(), result, matches));
            }
            String runStatus = matched == cases.size() ? "PASS" : "FAIL";
            jdbc.update("""
                    insert into platform.ai_grid_answer_key_runs
                        (id, environment_id, catalog_digest, status, total_cases, matched_cases,
                         executed_by, started_at, source_tenant_id, source_run_id, provenance_state)
                    values (:id, :environmentId, :digest, :status, :total, :matched, :actor, :started,
                            :sourceTenantId, :sourceRunId, 'PLATFORM_RUN_BOUND')
                    """, new MapSqlParameterSource().addValue("id", runId).addValue("environmentId", environmentId)
                    .addValue("digest", command.catalogDigest()).addValue("status", runStatus)
                    .addValue("total", cases.size()).addValue("matched", matched).addValue("actor", actor)
                    .addValue("sourceTenantId", command.sourceTenantId()).addValue("sourceRunId", command.sourceRunId())
                    .addValue("started", java.sql.Timestamp.from(
                            command.startedAt() == null ? Instant.now() : command.startedAt())));
            for (ResultInsert row : resultRows) {
                AssessmentProvenance assessment = provenance.assessments().get(row.command().caseKey());
                jdbc.update("""
                        insert into platform.ai_grid_answer_key_results
                            (id, run_id, case_id, observed_json, matched, mismatch_reason,
                             source_assessment_id, source_decision_fingerprint)
                        values (:id, :runId, :caseId, cast(:observed as jsonb), :matched, :reason,
                                :assessmentId, :decisionFingerprint)
                        """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("runId", runId)
                        .addValue("caseId", row.caseId()).addValue("observed", json(row.command().observed()))
                        .addValue("matched", row.matched())
                        .addValue("reason", row.matched() ? null : row.command().mismatchReason())
                        .addValue("assessmentId", assessment == null ? null : assessment.id())
                        .addValue("decisionFingerprint", assessment == null ? null : assessment.decisionFingerprint()));
            }
            if ("PASS".equals(runStatus)) {
                jdbc.update("update platform.ai_grid_answer_key_environments set last_verified_at = now() where id = :id",
                        Map.of("id", environmentId));
            }
            return answerKeyRun(runId);
        }));
    }

    private RunProvenance validateRunProvenance(RunCommand command, List<AnswerKeyCase> cases) {
        Map<String, ResultCommand> supplied = new HashMap<>();
        for (ResultCommand result : command.results()) {
            if (result == null || result.caseKey() == null) throw badRequest("Every result requires caseKey");
            if (supplied.put(result.caseKey(), result) != null) throw badRequest("Duplicate result: " + result.caseKey());
        }
        if (supplied.size() != cases.size() || cases.stream().anyMatch(c -> !supplied.containsKey(c.caseKey()))) {
            throw conflict("Run must report exactly one result for every answer-key case");
        }
        return tenantExecution.run(command.sourceTenantId(), () -> {
            Integer manifests = jdbc.queryForObject("""
                    select count(*) from ai_grid_snapshot_manifests where run_id = :runId
                    """, Map.of("runId", command.sourceRunId()), Integer.class);
            if (manifests == null || manifests == 0) {
                throw conflict("sourceRunId does not identify an immutable AI Grid snapshot for sourceTenantId");
            }
            Map<String, AssessmentProvenance> validated = new HashMap<>();
            for (AnswerKeyCase answerCase : cases) {
                ResultCommand result = supplied.get(answerCase.caseKey());
                if (answerCase.policyId() == null) {
                    if (result.sourceAssessmentId() != null) {
                        throw conflict("Non-policy answer-key case must not claim a source assessment: "
                                + answerCase.caseKey());
                    }
                    continue;
                }
                if (result.sourceAssessmentId() == null) {
                    throw conflict("Policy answer-key case requires sourceAssessmentId: " + answerCase.caseKey());
                }
                AssessmentProvenance assessment = jdbc.query("""
                        select a.id, a.policy_id, a.policy_version, a.applicability, a.decision,
                               a.decision_fingerprint,
                               exists (select 1 from findings f where f.assessment_id = a.id
                                        and f.status in ('OPEN','SUPPRESSED')) finding_present
                          from ai_grid_assessments a
                         where a.id = :assessmentId and a.run_id = :runId
                        """, Map.of("assessmentId", result.sourceAssessmentId(), "runId", command.sourceRunId()),
                        rs -> rs.next() ? new AssessmentProvenance(rs.getObject("id", UUID.class),
                                rs.getString("policy_id"), rs.getString("policy_version"),
                                rs.getString("applicability"), rs.getString("decision"),
                                rs.getString("decision_fingerprint"), rs.getBoolean("finding_present")) : null);
                if (assessment == null
                        || !answerCase.policyId().equals(assessment.policyId())
                        || !answerCase.policyVersion().equals(assessment.policyVersion())) {
                    throw conflict("sourceAssessmentId is not from the declared run and policy: "
                            + answerCase.caseKey());
                }
                if (assessment.decisionFingerprint() == null || assessment.decisionFingerprint().isBlank()) {
                    throw conflict("Source assessment has no deterministic decision fingerprint: "
                            + answerCase.caseKey());
                }
                JsonNode observed = objectMapper.valueToTree(result.observed());
                if (!assessment.applicability().equals(observed.path("applicability").asText())
                        || !assessment.decision().equals(observed.path("decisions").asText())
                        || assessment.findingPresent() != observed.path("findings").asBoolean()) {
                    throw conflict("Observed applicability, decision, or finding does not match source assessment: "
                            + answerCase.caseKey());
                }
                validated.put(answerCase.caseKey(), assessment);
            }
            return new RunProvenance(Map.copyOf(validated));
        });
    }

    public PrecisionReview createPrecisionReview(PrecisionReviewCommand command, String actor) {
        requireText(command.policyId(), "policyId");
        requireText(command.policyVersion(), "policyVersion");
        requireText(command.populationDefinition(), "populationDefinition");
        requireText(command.samplingMethod(), "samplingMethod");
        if (command.minimumSampleSize() <= 0) throw badRequest("minimumSampleSize must be positive");
        String digest = policyDigest(command.policyId(), command.policyVersion());
        return TenantContext.runAsPlatform(() -> transactions.execute(status -> {
            UUID id = UUID.randomUUID();
            jdbc.update("""
                    insert into platform.ai_grid_precision_reviews
                        (id, policy_id, policy_version, population_definition, sampling_method,
                         minimum_sample_size, confidence_level, precision_threshold,
                         material_change_digest, created_by)
                    values (:id, :policyId, :version, :population, :sampling, :minimum,
                            :confidence, :threshold, :digest, :actor)
                    """, new MapSqlParameterSource().addValue("id", id).addValue("policyId", command.policyId())
                    .addValue("version", command.policyVersion()).addValue("population", command.populationDefinition())
                    .addValue("sampling", command.samplingMethod()).addValue("minimum", command.minimumSampleSize())
                    .addValue("confidence", command.confidenceLevel() == null ? 0.95 : command.confidenceLevel())
                    .addValue("threshold", command.precisionThreshold() == null ? 0.95 : command.precisionThreshold())
                    .addValue("digest", digest).addValue("actor", actor));
            return precisionReview(id);
        }));
    }

    public PrecisionSample addPrecisionSample(UUID reviewId, PrecisionSampleCommand command) {
        requireText(command.sampleKey(), "sampleKey");
        requireText(command.provider(), "provider");
        requireText(command.resourceFamily(), "resourceFamily");
        requireText(command.severity(), "severity");
        requireText(command.observedOutcome(), "observedOutcome");
        requireText(command.evidenceReference(), "evidenceReference");
        return TenantContext.runAsPlatform(() -> transactions.execute(status -> {
            assertReviewOpen(reviewId);
            UUID id = UUID.randomUUID();
            jdbc.update("""
                    insert into platform.ai_grid_precision_samples
                        (id, review_id, sample_key, provider, resource_family, severity,
                         observed_outcome, predicted_finding, evidence_reference)
                    values (:id, :reviewId, :key, :provider, :family, :severity, :outcome, :predicted, :evidence)
                    """, new MapSqlParameterSource().addValue("id", id).addValue("reviewId", reviewId)
                    .addValue("key", command.sampleKey()).addValue("provider", command.provider())
                    .addValue("family", command.resourceFamily()).addValue("severity", command.severity())
                    .addValue("outcome", command.observedOutcome()).addValue("predicted", command.predictedFinding())
                    .addValue("evidence", command.evidenceReference()));
            jdbc.update("update platform.ai_grid_precision_reviews set status = 'IN_REVIEW' where id = :id",
                    Map.of("id", reviewId));
            return precisionSample(id);
        }));
    }

    public void submitLabel(UUID reviewId, UUID sampleId, LabelCommand command, String actor) {
        if (!LABELS.contains(command.label())) throw badRequest("Invalid precision label");
        requireText(command.labelVersion(), "labelVersion");
        requireText(command.rationale(), "rationale");
        requireText(command.evidenceReference(), "evidenceReference");
        TenantContext.runAsPlatform(() -> transactions.executeWithoutResult(status -> {
            assertReviewOpen(reviewId);
            Boolean predicted = jdbc.query("""
                    select predicted_finding from platform.ai_grid_precision_samples
                     where id = :sampleId and review_id = :reviewId
                    """, Map.of("sampleId", sampleId, "reviewId", reviewId),
                    rs -> rs.next() ? rs.getBoolean(1) : null);
            if (predicted == null) throw notFound("Precision sample not found");
            if (predicted && !List.of("TRUE_POSITIVE", "FALSE_POSITIVE", "EXCLUDE").contains(command.label())) {
                throw badRequest("A predicted finding must be labelled TRUE_POSITIVE, FALSE_POSITIVE, or EXCLUDE");
            }
            if (!predicted && !List.of("TRUE_NEGATIVE", "FALSE_NEGATIVE", "EXCLUDE").contains(command.label())) {
                throw badRequest("A non-finding sample must be labelled TRUE_NEGATIVE, FALSE_NEGATIVE, or EXCLUDE");
            }
            jdbc.update("""
                    insert into platform.ai_grid_precision_labels
                        (id, sample_id, reviewer, label, label_version, rationale, evidence_reference)
                    values (:id, :sampleId, :reviewer, :label, :version, :rationale, :evidence)
                    """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("sampleId", sampleId)
                    .addValue("reviewer", actor).addValue("label", command.label())
                    .addValue("version", command.labelVersion()).addValue("rationale", command.rationale())
                    .addValue("evidence", command.evidenceReference()));
        }));
    }

    public void adjudicate(UUID reviewId, UUID sampleId, AdjudicationCommand command, String actor) {
        if (!LABELS.contains(command.finalLabel())) throw badRequest("Invalid final precision label");
        requireText(command.rationale(), "rationale");
        TenantContext.runAsPlatform(() -> transactions.executeWithoutResult(status -> {
            assertReviewOpen(reviewId);
            List<String> labels = jdbc.query("""
                    select l.label from platform.ai_grid_precision_labels l
                    join platform.ai_grid_precision_samples s on s.id = l.sample_id
                    where s.id = :sampleId and s.review_id = :reviewId and l.reviewer <> :actor
                    """, Map.of("sampleId", sampleId, "reviewId", reviewId, "actor", actor),
                    (rs, n) -> rs.getString(1));
            if (labels.size() < 2 || labels.stream().distinct().count() < 2) {
                throw conflict("Adjudication requires two disagreeing independent reviewer labels");
            }
            jdbc.update("""
                    insert into platform.ai_grid_precision_adjudications
                        (id, sample_id, final_label, rationale, adjudicated_by)
                    values (:id, :sampleId, :label, :rationale, :actor)
                    """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("sampleId", sampleId)
                    .addValue("label", command.finalLabel()).addValue("rationale", command.rationale())
                    .addValue("actor", actor));
        }));
    }

    public PrecisionReview assessBias(UUID reviewId, boolean passed, String rationale, String actor) {
        requireText(rationale, "rationale");
        return TenantContext.runAsPlatform(() -> transactions.execute(status -> {
            assertReviewOpen(reviewId);
            jdbc.update("""
                    update platform.ai_grid_precision_reviews
                       set bias_status = :bias, bias_rationale = :rationale, bias_reviewed_by = :actor
                     where id = :id
                    """, Map.of("bias", passed ? "PASSED" : "FAILED", "rationale", rationale,
                    "actor", actor, "id", reviewId));
            return precisionReview(reviewId);
        }));
    }

    public PrecisionReview finalizePrecisionReview(UUID reviewId) {
        return TenantContext.runAsPlatform(() -> transactions.execute(status -> {
            PrecisionReview review = precisionReview(reviewId);
            assertReviewOpen(reviewId);
            String severity = policySeverity(review.policyId(), review.policyVersion());
            int reviewersRequired = List.of("HIGH", "CRITICAL").contains(severity) ? 2 : 1;
            List<ResolvedSample> samples = jdbc.query("""
                    select s.id, s.predicted_finding,
                           array_agg(l.label order by l.reviewer) labels,
                           count(distinct l.reviewer) reviewer_count,
                           a.final_label
                      from platform.ai_grid_precision_samples s
                      left join platform.ai_grid_precision_labels l on l.sample_id = s.id
                      left join platform.ai_grid_precision_adjudications a on a.sample_id = s.id
                     where s.review_id = :id
                     group by s.id, s.predicted_finding, a.final_label
                     order by s.id
                    """, Map.of("id", reviewId), (rs, n) -> {
                String[] labels = (String[]) rs.getArray("labels").getArray();
                return new ResolvedSample(rs.getBoolean("predicted_finding"), List.of(labels),
                        rs.getInt("reviewer_count"), rs.getString("final_label"));
            });
            if (samples.isEmpty()) throw conflict("Precision review has no samples");
            int tp = 0;
            int fp = 0;
            for (ResolvedSample sample : samples) {
                if (sample.reviewerCount() < reviewersRequired) {
                    throw conflict("Every sample requires " + reviewersRequired + " independent reviewer label(s)");
                }
                String resolved = resolve(sample);
                if (resolved == null) {
                    jdbc.update("update platform.ai_grid_precision_reviews set status = 'ADJUDICATION' where id = :id",
                            Map.of("id", reviewId));
                    throw conflict("Reviewer disagreement requires adjudication");
                }
                if (sample.predictedFinding() && "TRUE_POSITIVE".equals(resolved)) tp++;
                if (sample.predictedFinding() && "FALSE_POSITIVE".equals(resolved)) fp++;
            }
            int positive = tp + fp;
            Double precision = positive == 0 || positive < review.minimumSampleSize()
                    || !"PASSED".equals(review.biasStatus()) ? null : (double) tp / positive;
            double[] interval = precision == null ? new double[]{Double.NaN, Double.NaN}
                    : wilson(tp, positive, review.confidenceLevel());
            boolean passed = precision != null && interval[0] >= review.precisionThreshold();
            jdbc.update("""
                    update platform.ai_grid_precision_reviews
                       set status = :status, resolved_positive_samples = :positive,
                           true_positives = :tp, false_positives = :fp, precision_value = :precision,
                           confidence_lower = :lower, confidence_upper = :upper, finalized_at = now()
                     where id = :id
                    """, new MapSqlParameterSource().addValue("status", passed ? "PASSED" : "FAILED")
                    .addValue("positive", positive).addValue("tp", tp).addValue("fp", fp)
                    .addValue("precision", precision).addValue("lower", precision == null ? null : interval[0])
                    .addValue("upper", precision == null ? null : interval[1]).addValue("id", reviewId));
            return precisionReview(reviewId);
        }));
    }

    public ReleaseDecision publishPolicy(String policyId, String version, String actor) {
        return TenantContext.runAsPlatform(() -> transactions.execute(status -> {
            PolicyCandidate candidate = policyCandidate(policyId, version);
            String digest = digest(candidate.digestMaterial());
            AnswerKeyGate answerKey = answerKeyGate(policyId, version, digest);
            PrecisionReview precision = List.of("HIGH", "CRITICAL").contains(candidate.severity())
                    ? passingPrecisionReview(policyId, version, digest) : null;
            List<String> blockers = new ArrayList<>();
            if (answerKey == null) blockers.add("No fresh, certified, passing answer-key run for this policy digest");
            if (List.of("HIGH", "CRITICAL").contains(candidate.severity()) && precision == null) {
                blockers.add("No passing dual-reviewed precision review for this policy digest");
            }
            UUID decisionId = UUID.randomUUID();
            if (!blockers.isEmpty()) {
                String reason = String.join("; ", blockers);
                insertReleaseDecision(decisionId, policyId, version, "BLOCKED", answerKey, precision, reason, actor);
                return new ReleaseDecision(decisionId, policyId, version, false, reason,
                        answerKey == null ? null : answerKey.runId(), precision == null ? null : precision.id());
            }
            if (!List.of("VALIDATED", "APPROVED", "CANARY", "PUBLISHED").contains(candidate.lifecycle())) {
                String reason = "Policy lifecycle must be VALIDATED, APPROVED, CANARY, or PUBLISHED";
                insertReleaseDecision(decisionId, policyId, version, "BLOCKED", answerKey, precision, reason, actor);
                return new ReleaseDecision(decisionId, policyId, version, false, reason,
                        answerKey.runId(), precision == null ? null : precision.id());
            }
            jdbc.update("""
                    update platform.ai_grid_policy_versions set lifecycle = 'RETIRED'
                     where policy_id = :policyId and lifecycle = 'PUBLISHED' and version <> :version
                    """, Map.of("policyId", policyId, "version", version));
            jdbc.update("""
                    update platform.ai_grid_policy_versions
                       set lifecycle = 'PUBLISHED', approved_by = :actor,
                           approved_at = coalesce(approved_at, now()), published_at = now()
                     where policy_id = :policyId and version = :version
                    """, Map.of("actor", actor, "policyId", policyId, "version", version));
            String reason = "Answer-key and precision release gates passed";
            insertReleaseDecision(decisionId, policyId, version, "APPROVED", answerKey, precision, reason, actor);
            return new ReleaseDecision(decisionId, policyId, version, true, reason, answerKey.runId(),
                    precision == null ? null : precision.id());
        }));
    }

    public String policyDigest(String policyId, String version) {
        return TenantContext.runAsPlatform(() -> digest(policyCandidate(policyId, version).digestMaterial()));
    }

    public ReleaseReadiness releaseReadiness(String policyId, String version) {
        return TenantContext.runAsPlatform(() -> {
            PolicyCandidate candidate = policyCandidate(policyId, version);
            String digest = digest(candidate.digestMaterial());
            AnswerKeyGate answerKey = answerKeyGate(policyId, version, digest);
            PrecisionReview precision = List.of("HIGH", "CRITICAL").contains(candidate.severity())
                    ? passingPrecisionReview(policyId, version, digest) : null;
            LatestDecision latest = jdbc.query("""
                    select decision, reason, decided_at from platform.ai_grid_policy_release_decisions
                     where policy_id = :policyId and policy_version = :version
                     order by decided_at desc limit 1
                    """, Map.of("policyId", policyId, "version", version), rs -> rs.next()
                    ? new LatestDecision(rs.getString("decision"), rs.getString("reason"),
                    rs.getTimestamp("decided_at").toInstant()) : null);
            List<String> blockers = new ArrayList<>();
            if (answerKey == null) blockers.add("FRESH_PASSING_ANSWER_KEY_REQUIRED");
            if (List.of("HIGH", "CRITICAL").contains(candidate.severity()) && precision == null) {
                blockers.add("PASSING_PRECISION_REVIEW_REQUIRED");
            }
            if (!List.of("VALIDATED", "APPROVED", "CANARY", "PUBLISHED").contains(candidate.lifecycle())) {
                blockers.add("POLICY_LIFECYCLE_NOT_RELEASABLE");
            }
            return new ReleaseReadiness(policyId, version, candidate.lifecycle(), candidate.severity(), digest,
                    blockers.isEmpty(), blockers, answerKey == null ? null : answerKey.runId(),
                    precision == null ? null : precision.id(), latest == null ? null : latest.decision(),
                    latest == null ? null : latest.reason(), latest == null ? null : latest.decidedAt());
        });
    }

    public List<AnswerKeyEnvironment> environments() {
        return TenantContext.runAsPlatform(() -> jdbc.query("""
                select * from platform.ai_grid_answer_key_environments
                 order by environment_key, created_at desc
                """, (rs, n) -> mapEnvironment(rs)));
    }

    public List<AnswerKeyCase> cases(UUID environmentId) {
        return TenantContext.runAsPlatform(() -> jdbc.query("""
                select id, environment_id, case_key, scenario, policy_id, policy_version,
                       expected_applicability, expected_decision, expected_finding,
                       expected_json::text, label_version, rationale, evidence_reference
                  from platform.ai_grid_answer_key_cases where environment_id = :id order by case_key
                """, Map.of("id", environmentId), (rs, n) -> new AnswerKeyCase(rs.getObject("id", UUID.class),
                rs.getObject("environment_id", UUID.class), rs.getString("case_key"), rs.getString("scenario"),
                rs.getString("policy_id"), rs.getString("policy_version"), rs.getString("expected_applicability"),
                rs.getString("expected_decision"), (Boolean) rs.getObject("expected_finding"),
                rs.getString("expected_json"), rs.getString("label_version"), rs.getString("rationale"),
                rs.getString("evidence_reference"))));
    }

    public PrecisionReview precisionReview(UUID id) {
        return TenantContext.runAsPlatform(() -> {
            PrecisionReview result = jdbc.query("""
                    select * from platform.ai_grid_precision_reviews where id = :id
                    """, Map.of("id", id), rs -> rs.next() ? mapPrecisionReview(rs) : null);
            if (result == null) throw notFound("Precision review not found");
            return result;
        });
    }

    private AnswerKeyEnvironment environment(UUID id) {
        AnswerKeyEnvironment result = jdbc.query("select * from platform.ai_grid_answer_key_environments where id = :id",
                Map.of("id", id), rs -> rs.next() ? mapEnvironment(rs) : null);
        if (result == null) throw notFound("Answer-key environment not found");
        return result;
    }

    private AnswerKeyCase answerKeyCase(UUID id) {
        return jdbc.queryForObject("""
                select id, environment_id, case_key, scenario, policy_id, policy_version,
                       expected_applicability, expected_decision, expected_finding,
                       expected_json::text, label_version, rationale, evidence_reference
                  from platform.ai_grid_answer_key_cases where id = :id
                """, Map.of("id", id), (rs, n) -> new AnswerKeyCase(rs.getObject("id", UUID.class),
                rs.getObject("environment_id", UUID.class), rs.getString("case_key"), rs.getString("scenario"),
                rs.getString("policy_id"), rs.getString("policy_version"), rs.getString("expected_applicability"),
                rs.getString("expected_decision"), (Boolean) rs.getObject("expected_finding"),
                rs.getString("expected_json"), rs.getString("label_version"), rs.getString("rationale"),
                rs.getString("evidence_reference")));
    }

    private AnswerKeyRun answerKeyRun(UUID id) {
        return jdbc.queryForObject("""
                select id, environment_id, catalog_digest, status, total_cases, matched_cases,
                       executed_by, started_at, completed_at, source_tenant_id, source_run_id, provenance_state
                  from platform.ai_grid_answer_key_runs where id = :id
                """, Map.of("id", id), (rs, n) -> new AnswerKeyRun(rs.getObject("id", UUID.class),
                rs.getObject("environment_id", UUID.class), rs.getString("catalog_digest"), rs.getString("status"),
                rs.getInt("total_cases"), rs.getInt("matched_cases"), rs.getString("executed_by"),
                rs.getTimestamp("started_at").toInstant(), rs.getTimestamp("completed_at").toInstant(),
                rs.getObject("source_tenant_id", UUID.class), rs.getObject("source_run_id", UUID.class),
                rs.getString("provenance_state")));
    }

    private PrecisionSample precisionSample(UUID id) {
        return jdbc.queryForObject("""
                select id, review_id, sample_key, provider, resource_family, severity,
                       observed_outcome, predicted_finding, evidence_reference
                  from platform.ai_grid_precision_samples where id = :id
                """, Map.of("id", id), (rs, n) -> new PrecisionSample(rs.getObject("id", UUID.class),
                rs.getObject("review_id", UUID.class), rs.getString("sample_key"), rs.getString("provider"),
                rs.getString("resource_family"), rs.getString("severity"), rs.getString("observed_outcome"),
                rs.getBoolean("predicted_finding"), rs.getString("evidence_reference")));
    }

    private void assertEnvironmentLifecycle(UUID id, String lifecycle) {
        if (!lifecycle.equals(environment(id).lifecycle())) throw conflict("Answer-key environment is immutable after certification");
    }

    private void assertReviewOpen(UUID reviewId) {
        String state = jdbc.query("select status from platform.ai_grid_precision_reviews where id = :id",
                Map.of("id", reviewId), rs -> rs.next() ? rs.getString(1) : null);
        if (state == null) throw notFound("Precision review not found");
        if (List.of("PASSED", "FAILED", "STALE").contains(state)) throw conflict("Precision review is finalized");
    }

    private String resolve(ResolvedSample sample) {
        if (sample.finalLabel() != null) return sample.finalLabel();
        return sample.labels().stream().distinct().count() == 1 ? sample.labels().get(0) : null;
    }

    private AnswerKeyGate answerKeyGate(String policyId, String version, String digest) {
        return jdbc.query("""
                select r.id run_id, e.id environment_id
                  from platform.ai_grid_answer_key_runs r
                  join platform.ai_grid_answer_key_environments e on e.id = r.environment_id
                 where e.lifecycle = 'CERTIFIED' and e.review_due_at > now()
                   and r.status = 'PASS' and r.catalog_digest = :digest
                   and r.provenance_state = 'PLATFORM_RUN_BOUND'
                   and exists (select 1 from platform.ai_grid_answer_key_cases c
                                where c.environment_id = e.id and c.policy_id = :policyId
                                  and c.policy_version = :version)
                 order by r.completed_at desc limit 1
                """, Map.of("digest", digest, "policyId", policyId, "version", version),
                rs -> rs.next() ? new AnswerKeyGate(rs.getObject("run_id", UUID.class),
                        rs.getObject("environment_id", UUID.class)) : null);
    }

    private PrecisionReview passingPrecisionReview(String policyId, String version, String digest) {
        return jdbc.query("""
                select * from platform.ai_grid_precision_reviews
                 where policy_id = :policyId and policy_version = :version
                   and material_change_digest = :digest and status = 'PASSED'
                 order by finalized_at desc limit 1
                """, Map.of("policyId", policyId, "version", version, "digest", digest),
                rs -> rs.next() ? mapPrecisionReview(rs) : null);
    }

    private PolicyCandidate policyCandidate(String policyId, String version) {
        PolicyCandidate candidate = jdbc.query("""
                select severity, lifecycle, concat_ws('|', policy_id, version, name, description, severity,
                       workflow_class, default_selection, artifact_types_json::text, native_kinds_json::text,
                       required_capabilities_json::text, required_relationships_json::text,
                       required_resource_families_json::text, required_facts_json::text,
                       predicate_json::text, reason_code, remediation, framework_mappings_json::text,
                       scope_resolution) digest_material
                  from platform.ai_grid_policy_versions where policy_id = :policyId and version = :version
                """, Map.of("policyId", policyId, "version", version), rs -> rs.next()
                ? new PolicyCandidate(rs.getString("severity"), rs.getString("lifecycle"), rs.getString("digest_material"))
                : null);
        if (candidate == null) throw notFound("AI Grid policy version not found");
        return candidate;
    }

    private String policySeverity(String policyId, String version) {
        return policyCandidate(policyId, version).severity();
    }

    private void insertReleaseDecision(UUID id, String policyId, String version, String decision,
                                       AnswerKeyGate answerKey, PrecisionReview precision, String reason, String actor) {
        jdbc.update("""
                insert into platform.ai_grid_policy_release_decisions
                    (id, policy_id, policy_version, decision, answer_key_run_id,
                     precision_review_id, reason, decided_by)
                values (:id, :policyId, :version, :decision, :answerKey, :precision, :reason, :actor)
                """, new MapSqlParameterSource().addValue("id", id).addValue("policyId", policyId)
                .addValue("version", version).addValue("decision", decision)
                .addValue("answerKey", answerKey == null ? null : answerKey.runId())
                .addValue("precision", precision == null ? null : precision.id())
                .addValue("reason", reason).addValue("actor", actor));
    }

    private AnswerKeyEnvironment mapEnvironment(java.sql.ResultSet rs) throws java.sql.SQLException {
        return new AnswerKeyEnvironment(rs.getObject("id", UUID.class), rs.getString("environment_key"),
                rs.getString("version"), rs.getString("provider"), rs.getString("resource_family"),
                rs.getString("lifecycle"), rs.getString("engineering_owner"), rs.getString("security_reviewer"),
                rs.getString("provider_api_versions_json"), rs.getString("expected_economics_json"),
                rs.getString("change_summary"), instant(rs, "certified_at"), instant(rs, "last_verified_at"),
                rs.getTimestamp("review_due_at").toInstant(), rs.getString("created_by"),
                rs.getTimestamp("created_at").toInstant());
    }

    private PrecisionReview mapPrecisionReview(java.sql.ResultSet rs) throws java.sql.SQLException {
        return new PrecisionReview(rs.getObject("id", UUID.class), rs.getString("policy_id"),
                rs.getString("policy_version"), rs.getString("population_definition"), rs.getString("sampling_method"),
                rs.getInt("minimum_sample_size"), rs.getDouble("confidence_level"),
                rs.getDouble("precision_threshold"), rs.getString("material_change_digest"),
                rs.getString("bias_status"), rs.getString("bias_rationale"), rs.getString("bias_reviewed_by"),
                rs.getString("status"), rs.getInt("resolved_positive_samples"), rs.getInt("true_positives"),
                rs.getInt("false_positives"), nullableDouble(rs, "precision_value"),
                nullableDouble(rs, "confidence_lower"), nullableDouble(rs, "confidence_upper"),
                instant(rs, "finalized_at"), rs.getString("created_by"), rs.getTimestamp("created_at").toInstant());
    }

    private Double nullableDouble(java.sql.ResultSet rs, String column) throws java.sql.SQLException {
        Object value = rs.getObject(column);
        return value == null ? null : ((Number) value).doubleValue();
    }

    private Instant instant(java.sql.ResultSet rs, String column) throws java.sql.SQLException {
        java.sql.Timestamp timestamp = rs.getTimestamp(column);
        return timestamp == null ? null : timestamp.toInstant();
    }

    private String json(Object value) {
        try {
            return objectMapper.writeValueAsString(value == null ? Map.of() : value);
        } catch (JsonProcessingException ex) {
            throw badRequest("Invalid JSON payload");
        }
    }

    private JsonNode parse(String value) {
        try {
            return objectMapper.readTree(value);
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("Stored answer-key JSON is invalid", ex);
        }
    }

    private String digest(String value) {
        try {
            return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private double[] wilson(int successes, int total, double confidenceLevel) {
        double z = confidenceLevel >= 0.99 ? 2.575829 : confidenceLevel >= 0.95 ? 1.959964 : 1.644854;
        double p = (double) successes / total;
        double denominator = 1 + z * z / total;
        double centre = (p + z * z / (2 * total)) / denominator;
        double margin = z * Math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denominator;
        return new double[]{Math.max(0, centre - margin), Math.min(1, centre + margin)};
    }

    private void requireText(String value, String field) {
        if (value == null || value.isBlank()) throw badRequest(field + " is required");
    }

    private ResponseStatusException badRequest(String message) { return new ResponseStatusException(HttpStatus.BAD_REQUEST, message); }
    private ResponseStatusException conflict(String message) { return new ResponseStatusException(HttpStatus.CONFLICT, message); }
    private ResponseStatusException notFound(String message) { return new ResponseStatusException(HttpStatus.NOT_FOUND, message); }
    private record ResultInsert(UUID caseId, ResultCommand command, boolean matched) {}
    private record RunProvenance(Map<String, AssessmentProvenance> assessments) {}
    private record AssessmentProvenance(UUID id, String policyId, String policyVersion, String applicability,
                                        String decision, String decisionFingerprint, boolean findingPresent) {}
    private record ResolvedSample(boolean predictedFinding, List<String> labels, int reviewerCount, String finalLabel) {}
    private record PolicyCandidate(String severity, String lifecycle, String digestMaterial) {}
    private record AnswerKeyGate(UUID runId, UUID environmentId) {}
    private record LatestDecision(String decision, String reason, Instant decidedAt) {}

    public record EnvironmentCommand(String environmentKey, String version, String provider, String resourceFamily,
                                     String engineeringOwner, String securityReviewer,
                                     Map<String, Object> providerApiVersions, Map<String, Object> expectedEconomics,
                                     String changeSummary, Instant reviewDueAt) {}
    public record CaseCommand(String caseKey, String scenario, String policyId, String policyVersion,
                              String expectedApplicability, String expectedDecision, Boolean expectedFinding,
                              Map<String, Object> expected, String labelVersion, String rationale,
                              String evidenceReference) {}
    public record RunCommand(UUID sourceTenantId, UUID sourceRunId, String catalogDigest,
                             Instant startedAt, List<ResultCommand> results) {}
    public record ResultCommand(String caseKey, UUID sourceAssessmentId,
                                Map<String, Object> observed, String mismatchReason) {}
    public record PrecisionReviewCommand(String policyId, String policyVersion, String populationDefinition,
                                         String samplingMethod, int minimumSampleSize, Double confidenceLevel,
                                         Double precisionThreshold) {}
    public record PrecisionSampleCommand(String sampleKey, String provider, String resourceFamily, String severity,
                                         String observedOutcome, boolean predictedFinding, String evidenceReference) {}
    public record LabelCommand(String label, String labelVersion, String rationale, String evidenceReference) {}
    public record AdjudicationCommand(String finalLabel, String rationale) {}
    public record AnswerKeyEnvironment(UUID id, String environmentKey, String version, String provider,
                                       String resourceFamily, String lifecycle, String engineeringOwner,
                                       String securityReviewer, String providerApiVersionsJson,
                                       String expectedEconomicsJson, String changeSummary, Instant certifiedAt,
                                       Instant lastVerifiedAt, Instant reviewDueAt, String createdBy, Instant createdAt) {}
    public record AnswerKeyCase(UUID id, UUID environmentId, String caseKey, String scenario, String policyId,
                                String policyVersion, String expectedApplicability, String expectedDecision,
                                Boolean expectedFinding, String expectedJson, String labelVersion,
                                String rationale, String evidenceReference) {}
    public record AnswerKeyRun(UUID id, UUID environmentId, String catalogDigest, String status, int totalCases,
                               int matchedCases, String executedBy, Instant startedAt, Instant completedAt,
                               UUID sourceTenantId, UUID sourceRunId, String provenanceState) {}
    public record PrecisionReview(UUID id, String policyId, String policyVersion, String populationDefinition,
                                  String samplingMethod, int minimumSampleSize, double confidenceLevel,
                                  double precisionThreshold, String materialChangeDigest, String biasStatus,
                                  String biasRationale, String biasReviewedBy, String status,
                                  int resolvedPositiveSamples, int truePositives, int falsePositives,
                                  Double precisionValue, Double confidenceLower, Double confidenceUpper,
                                  Instant finalizedAt, String createdBy, Instant createdAt) {}
    public record PrecisionSample(UUID id, UUID reviewId, String sampleKey, String provider, String resourceFamily,
                                  String severity, String observedOutcome, boolean predictedFinding,
                                  String evidenceReference) {}
    public record ReleaseDecision(UUID id, String policyId, String policyVersion, boolean published, String reason,
                                  UUID answerKeyRunId, UUID precisionReviewId) {}
    public record ReleaseReadiness(String policyId, String policyVersion, String lifecycle, String severity,
                                   String catalogDigest, boolean ready, List<String> blockers,
                                   UUID answerKeyRunId, UUID precisionReviewId, String latestDecision,
                                   String latestDecisionReason, Instant latestDecisionAt) {}
}
