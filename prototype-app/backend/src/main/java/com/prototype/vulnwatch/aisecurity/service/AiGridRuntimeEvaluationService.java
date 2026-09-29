package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * Bounded, read-only evaluator for execution-subject runtime policies.
 *
 * <p>Runtime policies are not artifact-subject policies: their subject is an execution, they read
 * the runtime metadata tables rather than snapshot facts, and they are deliberately excluded from
 * {@link AiGridAssessmentService}'s artifact loop. Absence of a governed field never becomes
 * {@code PASS} — an unpopulated decision field yields {@code UNKNOWN}, and a decision family the
 * provider cannot supply at event scope yields {@code NOT_ASSESSED}.
 */
@Service
public class AiGridRuntimeEvaluationService {
    private static final Logger LOG = LoggerFactory.getLogger(AiGridRuntimeEvaluationService.class);

    /** Hard ceiling on executions examined per policy, independent of the package's own limits. */
    static final int MAX_EXECUTIONS_PER_POLICY = 2000;
    private static final Set<String> SEQUENCE_OPERATORS = Set.of("EQ", "NE", "IN", "NOT_IN", "EXISTS");

    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectMapper objectMapper;
    private final AiGridFindingService findings;
    private final AiGridSnapshotService snapshots;
    private final AiGridCapabilityService capabilities;
    private final int lookbackDays;

    public AiGridRuntimeEvaluationService(NamedParameterJdbcTemplate jdbc, ObjectMapper objectMapper,
                                           AiGridFindingService findings, AiGridSnapshotService snapshots,
                                           AiGridCapabilityService capabilities,
                                           @Value("${app.ai-security.runtime.evaluation-lookback-days:14}") int lookbackDays) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
        this.findings = findings;
        this.snapshots = snapshots;
        this.capabilities = capabilities;
        this.lookbackDays = Math.max(1, lookbackDays);
    }

    /** Evaluates every enabled runtime policy for the tenant, anchored to the triggering run. */
    public int evaluateRun(Tenant tenant, UUID runId) {
        List<RuntimePolicy> policies = loadRuntimePolicies(tenant);
        if (policies.isEmpty()) return 0;
        Map<String, String> selections = loadSelections();
        Map<String, Map<String, Object>> parameters = loadParameters();
        Map<String, RuntimeField> registry = loadFieldRegistry();
        Map<String, List<String>> requiredCapabilities = loadRequiredCapabilities(policies);
        Map<AiGridCapabilityService.CapabilityKey, AiGridCapabilityService.CapabilityState> capabilityIndex =
                capabilities.latestIndex();
        Instant evaluationAsOf = Instant.now();
        Instant windowStart = evaluationAsOf.minus(Duration.ofDays(lookbackDays));
        boolean findingChanged = false;
        int evaluated = 0;
        for (RuntimePolicy policy : policies) {
            String selection = selections.getOrDefault(policy.id(), policy.defaultSelection());
            // PREVIEW and DISABLED stay inert until a tenant explicitly overrides them, so a new
            // runtime package never evaluates or opens findings on distribution alone.
            if (!"ENABLED".equals(selection) && !"REQUIRED".equals(selection)) continue;
            evaluated++;
            List<String> providers = isAnyProvider(policy.provider())
                    ? runtimeProviders(windowStart) : List.of(policy.provider());
            for (String provider : providers) {
                RuntimePolicy scoped = policy.withProvider(provider);
                // A capability from one provider cannot authorize evaluation of another provider's evidence.
                List<String> gaps = capabilities.runtimeGaps(capabilityIndex, provider,
                        requiredCapabilities.getOrDefault(policy.id(), List.of()));
                if (!gaps.isEmpty()) {
                    persistPolicyWide(tenant, runId, evaluationAsOf, scoped, selection, "NO_DECISION",
                            "CAPABILITY_UNAVAILABLE", gaps,
                            Map.of("remediation", Map.of("value", capabilities.remediation(
                                    requiredCapabilities.getOrDefault(policy.id(), List.of())))));
                    continue;
                }
                try {
                    findingChanged |= switch (scoped.evaluationMode()) {
                        case "RUNTIME_FACTS" -> evaluateFacts(tenant, runId, evaluationAsOf, windowStart,
                                scoped, selection, registry);
                        case "RUNTIME_SEQUENCE" -> evaluateSequence(tenant, runId, evaluationAsOf, windowStart,
                                scoped, selection, registry);
                        case "RUNTIME_COVERAGE" -> evaluateCoverage(tenant, runId, evaluationAsOf, windowStart,
                                scoped, selection);
                        default -> evaluateAggregate(tenant, runId, evaluationAsOf, windowStart,
                                scoped, selection, registry, parameters.getOrDefault(policy.id(), Map.of()));
                    };
                } catch (RuntimeException failure) {
                    LOG.warn("Runtime policy {} could not be evaluated for tenant {} provider {}",
                            policy.id(), tenant.getId(), provider, failure);
                    try {
                        persistPolicyUnknown(tenant, runId, evaluationAsOf, scoped, selection,
                                "RUNTIME_EVALUATION_FAILED",
                                List.of("evaluation:" + failure.getClass().getSimpleName()));
                    } catch (RuntimeException persistenceFailure) {
                        LOG.error("Runtime policy {} failure assessment could not be persisted for tenant {}",
                                policy.id(), tenant.getId(), persistenceFailure);
                    }
                }
            }
        }
        if (findingChanged) findings.refreshProjectionAfterCommit(tenant);
        return evaluated;
    }

    // ------------------------------------------------------------------- facts

    /**
     * Evaluates a bounded conjunction of execution-scoped conditions, one execution per subject.
     * All conditions must hold for the violation to be established; an unpopulated field settles
     * as {@code UNKNOWN} rather than satisfying or refuting the condition.
     */
    private boolean evaluateFacts(Tenant tenant, UUID runId, Instant evaluationAsOf, Instant windowStart,
                                  RuntimePolicy policy, String selection, Map<String, RuntimeField> registry) {
        JsonNode definition = policy.definition().path("runtimeFacts");
        List<FactCondition> conditions = new ArrayList<>();
        for (JsonNode condition : definition.path("conditions")) {
            String field = condition.path("field").asText();
            RuntimeField resolved = registry.get(field);
            if (resolved == null || !"ai_agent_executions".equals(resolved.sourceTable())) {
                return persistPolicyWide(tenant, runId, evaluationAsOf, policy, selection, "NO_DECISION",
                        "DECISION_SCOPE_UNSUPPORTED", List.of("field:" + field),
                        Map.of("unsupportedField", Map.of("value", field)));
            }
            conditions.add(new FactCondition(field, resolved.sourceColumn(),
                    condition.path("operator").asText(), values(condition.path("value"))));
        }
        if (conditions.isEmpty()) return false;

        List<Map<String, Object>> executions = jdbc.queryForList("""
                select execution.*,
                       case when manifest.approval_status='APPROVED' then 'APPROVED'
                             when manifest.approval_status='REVOKED' then 'REVOKED'
                             else 'UNAPPROVED' end version_approval_state
                       ,case when version.id is null then 'UNKNOWN'
                             when version.active then 'ACTIVE' else 'RETIRED' end version_lifecycle_state
                  from ai_agent_executions execution
                  left join ai_grid_approved_agent_manifests manifest
                    on manifest.version_artifact_id=execution.agent_version_artifact_id
                  left join ai_security_artifacts version on version.id=execution.agent_version_artifact_id
                 where execution.evidence_time >= :from
                   and (:anyProvider or execution.provider = :provider)
                 order by execution.evidence_time desc, execution.id
                 limit :limit
                """, new MapSqlParameterSource().addValue("from", Timestamp.from(windowStart))
                .addValue("anyProvider", isAnyProvider(policy.provider()))
                .addValue("provider", policy.provider())
                .addValue("limit", MAX_EXECUTIONS_PER_POLICY));
        boolean changed = false;
        for (Map<String, Object> execution : executions) {
            UUID executionId = (UUID) execution.get("id");
            Candidate candidate = new Candidate(executionId, executionId.toString(),
                    (Timestamp) execution.get("evidence_time"));
            String unpopulated = null;
            boolean allHold = true;
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("executionId", Map.of("value", executionId.toString()));
            for (FactCondition condition : conditions) {
                Object raw = execution.get(condition.column());
                if (raw == null && !"ABSENT".equals(condition.operator())) {
                    if (unpopulated == null) unpopulated = condition.field();
                    allHold = false;
                    continue;
                }
                evidence.put(condition.field(), Map.of("value", raw == null ? "" : String.valueOf(raw)));
                if (!holds(condition, raw)) allHold = false;
            }
            String decision;
            String reason;
            if (allHold) {
                decision = "FAIL";
                reason = policy.reasonCode();
            } else if (unpopulated != null) {
                decision = "NO_DECISION";
                reason = "RUNTIME_FIELD_UNPOPULATED";
            } else {
                decision = "PASS";
                reason = "RUNTIME_FACTS_NOT_MATCHED";
            }
            changed |= persist(tenant, runId, evaluationAsOf, policy, selection, "EXECUTION", executionId,
                    findingFingerprint(tenant.getId(), policy.id(), "EXECUTION", executionId.toString()),
                    "APPLICABLE", readiness(decision), decision, reason,
                    unpopulated == null ? List.of() : List.of("field:" + unpopulated), evidence, true);
        }
        return changed;
    }

    private boolean holds(FactCondition condition, Object raw) {
        String value = raw == null ? null : String.valueOf(raw);
        return switch (condition.operator()) {
            case "EXISTS" -> value != null;
            case "ABSENT" -> value == null;
            case "EQ", "IN" -> value != null && condition.values().contains(value);
            case "NE", "NOT_IN" -> value != null && !condition.values().contains(value);
            default -> false;
        };
    }

    // ---------------------------------------------------------------- sequence

    private boolean evaluateSequence(Tenant tenant, UUID runId, Instant evaluationAsOf, Instant windowStart,
                                     RuntimePolicy policy, String selection, Map<String, RuntimeField> registry) {
        JsonNode definition = policy.definition().path("runtimeSequence");
        List<SequenceStep> steps = new ArrayList<>();
        for (JsonNode step : definition.path("steps")) {
            JsonNode predicates = step.path("conditions").isArray() ? step.path("conditions") : null;
            List<EventPredicate> conditions = new ArrayList<>();
            if (predicates == null) {
                conditions.add(resolveEventPredicate(step, registry));
            } else {
                for (JsonNode predicate : predicates) conditions.add(resolveEventPredicate(predicate, registry));
            }
            EventPredicate unsupported = conditions.stream().filter(EventPredicate::unsupported).findFirst().orElse(null);
            if (unsupported != null || conditions.isEmpty()) {
                String field = unsupported == null ? "" : unsupported.field();
                return persistPolicyWide(tenant, runId, evaluationAsOf, policy, selection, "NO_DECISION",
                        "DECISION_SCOPE_UNSUPPORTED", List.of("field:" + field),
                        Map.of("unsupportedField", Map.of("value", field)));
            }
            steps.add(new SequenceStep(List.copyOf(conditions)));
        }
        if (steps.isEmpty()) return false;
        long maximumDurationSeconds = definition.path("maximumDurationSeconds").asLong();
        long allowedLatenessSeconds = definition.path("allowedLatenessSeconds").asLong();
        int maximumEvents = definition.path("maximumEventsExamined").asInt();
        RuntimeField dedupField = registry.get(definition.path("deduplicationKey").asText());
        if (dedupField == null) {
            return persistPolicyWide(tenant, runId, evaluationAsOf, policy, selection,
                    "NO_DECISION", "DECISION_SCOPE_UNSUPPORTED",
                    List.of("field:" + definition.path("deduplicationKey").asText()), Map.of());
        }

        List<Candidate> candidates = candidateExecutions(policy, windowStart, dedupField);
        if (candidates.size() > MAX_EXECUTIONS_PER_POLICY) {
            LOG.warn("Runtime policy {} examined the newest {} of {} candidate executions for tenant {}",
                    policy.id(), MAX_EXECUTIONS_PER_POLICY, candidates.size(), tenant.getId());
            candidates = candidates.subList(0, MAX_EXECUTIONS_PER_POLICY);
        }
        boolean changed = false;
        Set<String> settledDedupKeys = new LinkedHashSet<>();
        for (Candidate candidate : candidates) {
            List<Map<String, Object>> events = eventsFor(candidate.executionId(), maximumEvents + 1);
            if (events.size() > maximumEvents) {
                changed |= persistExecution(tenant, runId, evaluationAsOf, policy, selection, candidate,
                        candidate.dedupValue(), "NO_DECISION", "EVALUATION_BOUND_EXCEEDED",
                        List.of("bound:maximumEventsExamined"),
                        Map.of("maximumEventsExamined", Map.of("value", maximumEvents)), true);
                continue;
            }
            SequenceOutcome outcome = matchSequence(steps, events, maximumDurationSeconds);
            String decision;
            String reason;
            if (outcome.matched()) {
                decision = "FAIL";
                reason = policy.reasonCode();
            } else if (outcome.unpopulatedField() != null) {
                decision = "NO_DECISION";
                reason = decisionScopeUnsupported(candidate.executionId(), outcome.unpopulatedField())
                        ? "DECISION_SCOPE_UNSUPPORTED" : "RUNTIME_FIELD_UNPOPULATED";
            } else if (awaitingLateness(events, evaluationAsOf, allowedLatenessSeconds)) {
                decision = "NO_DECISION";
                reason = "AWAITING_LATENESS_WINDOW";
            } else {
                decision = "PASS";
                reason = "RUNTIME_SEQUENCE_NOT_OBSERVED";
            }
            // The deduplication key collapses repeated violations of the same policy onto one
            // finding. Later executions sharing a key still record their assessment, but only the
            // first reconciles — otherwise the same finding would be opened and closed in a loop.
            boolean firstForKey = settledDedupKeys.add(candidate.dedupValue());
            Map<String, Object> evidence = sequenceEvidence(policy, candidate, outcome, events, registry);
            changed |= persistExecution(tenant, runId, evaluationAsOf, policy, selection, candidate,
                    candidate.dedupValue(), decision, reason,
                    outcome.unpopulatedField() == null ? List.of() : List.of("field:" + outcome.unpopulatedField()),
                    evidence, firstForKey);
        }
        return changed;
    }

    private SequenceOutcome matchSequence(List<SequenceStep> steps, List<Map<String, Object>> events,
                                          long maximumDurationSeconds) {
        int cursor = 0;
        List<UUID> matchedEventIds = new ArrayList<>();
        Instant first = null;
        Instant last = null;
        String unpopulated = null;
        for (Map<String, Object> event : events) {
            if (cursor >= steps.size()) break;
            SequenceStep step = steps.get(cursor);
            boolean matches = true;
            String missing = null;
            for (EventPredicate predicate : step.conditions()) {
                Object raw = event.get(predicate.column());
                if (raw == null) {
                    matches = false;
                    if (missing == null) missing = predicate.field();
                } else if (!matches(predicate, String.valueOf(raw))) {
                    matches = false;
                }
            }
            if (missing != null && unpopulated == null) unpopulated = missing;
            if (!matches) continue;
            Instant eventTime = ((Timestamp) event.get("event_time")).toInstant();
            if (first == null) first = eventTime;
            last = eventTime;
            matchedEventIds.add((UUID) event.get("id"));
            cursor++;
        }
        boolean matched = cursor >= steps.size();
        if (matched && first != null
                && Duration.between(first, last).getSeconds() > maximumDurationSeconds) {
            matched = false;
        }
        return new SequenceOutcome(matched, matched ? null : unpopulated, matchedEventIds, first, last);
    }

    private EventPredicate resolveEventPredicate(JsonNode predicate, Map<String, RuntimeField> registry) {
        String field = predicate.path("field").asText();
        RuntimeField resolved = registry.get(field);
        String operator = predicate.path("operator").asText();
        boolean unsupported = resolved == null || !"ai_agent_execution_events".equals(resolved.sourceTable())
                || !SEQUENCE_OPERATORS.contains(operator);
        return new EventPredicate(field, resolved == null ? "" : resolved.sourceColumn(), operator,
                values(predicate.path("value")), unsupported);
    }

    private boolean matches(EventPredicate predicate, String value) {
        return switch (predicate.operator()) {
            case "EXISTS" -> true;
            case "EQ" -> predicate.values().contains(value);
            case "NE" -> !predicate.values().contains(value);
            case "IN" -> predicate.values().contains(value);
            case "NOT_IN" -> !predicate.values().contains(value);
            default -> false;
        };
    }

    private boolean awaitingLateness(List<Map<String, Object>> events, Instant evaluationAsOf, long allowedLateness) {
        if (events.isEmpty() || allowedLateness <= 0) return false;
        Instant newest = events.stream().map(event -> {
            Object ingested = event.get("ingested_at");
            return ingested instanceof Timestamp timestamp ? timestamp.toInstant()
                    : ((Timestamp) event.get("event_time")).toInstant();
        }).max(Instant::compareTo).orElseThrow();
        return Duration.between(newest, evaluationAsOf).getSeconds() < allowedLateness;
    }

    private boolean decisionScopeUnsupported(UUID executionId, String eventField) {
        String executionColumn = switch (eventField) {
            case "event.approval_state" -> "approval_state";
            case "event.policy_state" -> "policy_state";
            default -> null;
        };
        if (executionColumn == null) return false;
        Boolean present = jdbc.queryForObject("select " + executionColumn
                        + " is not null from ai_agent_executions where id=:id",
                Map.of("id", executionId), Boolean.class);
        return Boolean.TRUE.equals(present);
    }

    // --------------------------------------------------------------- aggregate

    private boolean evaluateCoverage(Tenant tenant, UUID runId, Instant evaluationAsOf, Instant windowStart,
                                     RuntimePolicy policy, String selection) {
        JsonNode definition = policy.definition().path("runtimeCoverage");
        Instant from = evaluationAsOf.minusSeconds(definition.path("lookbackSeconds").asLong());
        if (from.isBefore(windowStart)) from = windowStart;
        int maximumRows = definition.path("maximumRowsExamined").asInt();
        int sampleSize = definition.path("sampleSize").asInt();
        long windowSeconds = definition.path("windowSeconds").asLong();
        List<Map<String, Object>> rows = jdbc.queryForList("""
                with incomplete as (
                    select e.id execution_id, e.provider, e.source workspace,
                           missing.capability_family, v.event_time,
                           to_timestamp(floor(extract(epoch from v.event_time) / :windowSeconds)
                               * :windowSeconds) window_start
                      from ai_agent_execution_events v
                      join ai_agent_executions e on e.id=v.execution_id and e.tenant_id=v.tenant_id
                      cross join lateral (values
                          ('RUNTIME_EVENT_DECISIONS', v.approval_state is null or v.policy_state is null),
                          ('RUNTIME_ACTION_OUTCOMES', v.action_outcome is null)
                      ) missing(capability_family, is_missing)
                     where v.event_time >= :from and missing.is_missing
                       and (:anyProvider or e.provider = :provider)
                       and v.action_category in ('WRITE','DELETE','SEND','EXECUTE','ADMIN','PAYMENT','PUBLISH')
                     order by v.event_time desc, v.id
                     limit :limit
                )
                select provider, workspace, capability_family, window_start,
                       count(*) raw_count, count(distinct execution_id) affected_count,
                       (array_agg(distinct execution_id))[1:cast(:sampleSize as integer)] sample_execution_ids,
                       (array_agg(execution_id order by event_time desc))[1] anchor_execution_id
                  from incomplete
                 group by provider, workspace, capability_family, window_start
                 order by window_start desc, provider, workspace, capability_family
                """, new MapSqlParameterSource().addValue("from", Timestamp.from(from))
                .addValue("windowSeconds", windowSeconds).addValue("limit", maximumRows + 1)
                .addValue("sampleSize", sampleSize)
                .addValue("anyProvider", isAnyProvider(policy.provider()))
                .addValue("provider", policy.provider()));
        long represented = rows.stream().mapToLong(row -> ((Number) row.get("raw_count")).longValue()).sum();
        if (represented > maximumRows) {
            return persistPolicyUnknown(tenant, runId, evaluationAsOf, policy, selection,
                    "EVALUATION_BOUND_EXCEEDED", List.of("bound:maximumRowsExamined"));
        }
        boolean changed = false;
        for (Map<String, Object> row : rows) {
            UUID anchor = (UUID) row.get("anchor_execution_id");
            String group = row.get("provider") + "|" + row.get("workspace") + "|"
                    + row.get("capability_family") + "|" + row.get("window_start");
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("provider", Map.of("value", row.get("provider")));
            evidence.put("workspace", Map.of("value", row.get("workspace")));
            evidence.put("capabilityFamily", Map.of("value", row.get("capability_family")));
            evidence.put("windowStart", Map.of("value", String.valueOf(row.get("window_start"))));
            evidence.put("affectedExecutionCount", Map.of("value", row.get("affected_count")));
            evidence.put("sampleExecutionIds", Map.of("value", row.get("sample_execution_ids")));
            changed |= persist(tenant, runId, evaluationAsOf, policy, selection, "EXECUTION", anchor,
                    findingFingerprint(tenant.getId(), policy.id(), "COVERAGE", group),
                    "APPLICABLE", "READY", "FAIL", policy.reasonCode(), List.of(), evidence, true);
        }
        return changed;
    }

    private boolean evaluateAggregate(Tenant tenant, UUID runId, Instant evaluationAsOf, Instant windowStart,
                                      RuntimePolicy policy, String selection, Map<String, RuntimeField> registry,
                                      Map<String, Object> parameters) {
        JsonNode definition = policy.definition().path("runtimeAggregate");
        String metric = definition.path("metric").asText();
        RuntimeField grouping = registry.get(definition.path("groupingKey").asText());
        // A grouping key must resolve to a real UUID subject. Grouping on a free-text column
        // would attribute the breach to something the graph cannot name.
        if (grouping == null || !grouping.physicalColumn() || !"UUID".equals(grouping.valueType())
                || !"ai_agent_executions".equals(grouping.sourceTable())) {
            return persistPolicyWide(tenant, runId, evaluationAsOf, policy, selection, "NO_DECISION",
                    "DECISION_SCOPE_UNSUPPORTED",
                    List.of("field:" + definition.path("groupingKey").asText()), Map.of());
        }
        long lookbackSeconds = definition.path("lookbackSeconds").asLong();
        Instant from = evaluationAsOf.minusSeconds(lookbackSeconds);
        if (from.isBefore(windowStart)) from = windowStart;
        int maximumRows = definition.path("maximumRowsExamined").asInt();
        String operator = definition.path("operator").asText();
        String thresholdParameter = definition.path("thresholdParameter").asText();
        Object override = thresholdParameter.isBlank() ? null : parameters.get(thresholdParameter);
        double threshold = override instanceof Number number ? number.doubleValue()
                : definition.path("threshold").asDouble();

        int maximumEvents = definition.path("maximumEventsExamined").asInt();
        AggregateRead aggregate = aggregateGroups(policy, grouping.sourceColumn(), metric, from,
                maximumRows, maximumEvents);
        if (aggregate.boundReason() != null) {
            return persistPolicyUnknown(tenant, runId, evaluationAsOf, policy, selection,
                    "EVALUATION_BOUND_EXCEEDED", List.of("bound:" + aggregate.boundReason()));
        }
        List<Map<String, Object>> groups = aggregate.groups();
        boolean changed = false;
        for (Map<String, Object> group : groups) {
            UUID groupValue = (UUID) group.get("group_value");
            UUID anchorExecution = (UUID) group.get("anchor_execution_id");
            long rows = ((Number) group.get("examined_rows")).longValue();
            long nullContributors = ((Number) group.get("null_contributors")).longValue();
            Number measured = (Number) group.get("measured");
            Candidate candidate = new Candidate(anchorExecution, groupValue.toString(),
                    (Timestamp) group.get("anchor_evidence_time"));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("groupingKey", Map.of("value", definition.path("groupingKey").asText()));
            evidence.put("groupValue", Map.of("value", groupValue.toString()));
            evidence.put("metric", Map.of("value", metric));
            evidence.put("executionsExamined", Map.of("value", rows));
            if (measured == null || nullContributors > 0) {
                // A partially populated metric can only understate the total, so a threshold
                // comparison against it could manufacture a PASS.
                changed |= persistAggregate(tenant, runId, evaluationAsOf, policy, selection, candidate,
                        groupValue.toString(), "NO_DECISION", "RUNTIME_METRIC_UNPOPULATED",
                        List.of("metric:" + metric), evidence);
                continue;
            }
            evidence.put("measuredValue", Map.of("value", measured.doubleValue()));
            evidence.put("threshold", Map.of("value", threshold));
            evidence.put("operator", Map.of("value", operator));
            boolean breached = compare(measured.doubleValue(), operator, threshold);
            changed |= persistAggregate(tenant, runId, evaluationAsOf, policy, selection, candidate,
                    groupValue.toString(), breached ? "FAIL" : "PASS",
                    breached ? policy.reasonCode() : "RUNTIME_AGGREGATE_WITHIN_THRESHOLD",
                    List.of(), evidence);
        }
        return changed;
    }

    private boolean compare(double measured, String operator, double threshold) {
        return switch (operator) {
            case "GT" -> measured > threshold;
            case "GTE" -> measured >= threshold;
            case "LT" -> measured < threshold;
            case "LTE" -> measured <= threshold;
            case "EQ" -> measured == threshold;
            case "NE" -> measured != threshold;
            default -> false;
        };
    }

    // ------------------------------------------------------------------ reads

    private List<RuntimePolicy> loadRuntimePolicies(Tenant tenant) {
        return jdbc.query("""
                select distinct on (p.policy_id)
                       p.policy_id, p.version, p.name, p.severity, p.provider, p.reason_code,
                       p.evaluation_mode, p.evaluation_definition_json::text definition,
                       coalesce(d.default_selection, p.default_selection) default_selection
                  from platform.ai_grid_policy_versions p
                  join platform.ai_grid_policy_distribution d
                    on d.policy_id = p.policy_id and d.available = true
                 where p.evaluation_mode in ('RUNTIME_FACTS', 'RUNTIME_SEQUENCE', 'RUNTIME_AGGREGATE',
                                             'RUNTIME_COVERAGE')
                   and p.lifecycle in ('VALIDATED', 'APPROVED', 'PUBLISHED', 'CANARY')
                   and platform.ai_grid_policy_visible_to_tenant(
                           d.available, d.rollout_stage, d.canary_tenant_ids_json, cast(:tenantId as uuid))
                 order by p.policy_id, p.published_at desc nulls last, p.version desc
                """, Map.of("tenantId", tenant.getId().toString()), (rs, n) -> new RuntimePolicy(
                rs.getString("policy_id"), rs.getString("version"), rs.getString("name"),
                rs.getString("severity"), rs.getString("provider"), rs.getString("reason_code"),
                rs.getString("evaluation_mode"), tree(rs.getString("definition")),
                rs.getString("default_selection")));
    }

    private Map<String, List<String>> loadRequiredCapabilities(List<RuntimePolicy> policies) {
        if (policies.isEmpty()) return Map.of();
        Map<String, List<String>> declared = jdbc.query("""
                select distinct on (policy_id) policy_id, required_capabilities_json::text capabilities
                  from platform.ai_grid_policy_versions
                 where policy_id in (:policyIds)
                 order by policy_id, published_at desc nulls last, version desc
                """, Map.of("policyIds", policies.stream().map(RuntimePolicy::id).toList()), rs -> {
            Map<String, List<String>> result = new LinkedHashMap<>();
            while (rs.next()) {
                List<String> values = new ArrayList<>();
                tree(rs.getString("capabilities")).forEach(value -> values.add(value.asText()));
                result.put(rs.getString("policy_id"), List.copyOf(values));
            }
            return result;
        });
        return declared == null ? Map.of() : declared;
    }

    private Map<String, String> loadSelections() {
        return jdbc.query("select policy_id, selection from ai_grid_policy_selections", rs -> {
            Map<String, String> result = new LinkedHashMap<>();
            while (rs.next()) result.putIfAbsent(rs.getString(1), rs.getString(2));
            return result;
        });
    }

    private Map<String, Map<String, Object>> loadParameters() {
        Map<String, Map<String, Object>> loaded = jdbc.query(
                "select policy_id, parameters_json::text from ai_grid_policy_parameters", rs -> {
            Map<String, Map<String, Object>> result = new LinkedHashMap<>();
            while (rs.next()) {
                JsonNode node = tree(rs.getString(2));
                Map<String, Object> values = new LinkedHashMap<>();
                node.fields().forEachRemaining(entry -> values.put(entry.getKey(), entry.getValue().isNumber()
                        ? entry.getValue().numberValue() : entry.getValue().asText()));
                result.put(rs.getString(1), Map.copyOf(values));
            }
            return result;
        });
        return loaded == null ? Map.of() : loaded;
    }

    private Map<String, RuntimeField> loadFieldRegistry() {
        return jdbc.query("""
                select field_key, source_table, source_column, value_type, physical_column
                  from platform.ai_grid_runtime_field_definitions
                 where lifecycle = 'ACTIVE' and predicate_eligible = true
                """, rs -> {
            Map<String, RuntimeField> result = new LinkedHashMap<>();
            while (rs.next()) {
                result.put(rs.getString(1), new RuntimeField(
                        rs.getString(2), rs.getString(3), rs.getString(4), rs.getBoolean(5)));
            }
            return result;
        });
    }

    private List<String> runtimeProviders(Instant windowStart) {
        return jdbc.queryForList("""
                select distinct provider from ai_agent_executions
                 where evidence_time >= :from order by provider
                """, Map.of("from", Timestamp.from(windowStart)), String.class);
    }

    private List<Candidate> candidateExecutions(RuntimePolicy policy, Instant windowStart, RuntimeField dedupField) {
        if (!dedupField.physicalColumn() || !"ai_agent_executions".equals(dedupField.sourceTable())) {
            throw new IllegalArgumentException("Runtime sequence deduplication key must be a physical execution field");
        }
        String dedupExpression = "e." + dedupField.sourceColumn();
        return jdbc.query("""
                select e.id, e.evidence_time, cast(%s as text) dedup_value
                  from ai_agent_executions e
                 where e.evidence_time >= :from
                   and (:anyProvider or e.provider = :provider)
                   and exists (select 1 from ai_agent_execution_events v
                                where v.execution_id = e.id and v.tenant_id = e.tenant_id)
                 order by e.evidence_time desc, e.id
                 limit :limit
                """.formatted(dedupExpression), new MapSqlParameterSource()
                .addValue("from", Timestamp.from(windowStart))
                .addValue("anyProvider", isAnyProvider(policy.provider()))
                .addValue("provider", policy.provider())
                .addValue("limit", MAX_EXECUTIONS_PER_POLICY + 1), (rs, n) -> new Candidate(
                rs.getObject("id", UUID.class),
                rs.getString("dedup_value") == null ? rs.getObject("id", UUID.class).toString()
                        : rs.getString("dedup_value"),
                rs.getTimestamp("evidence_time")));
    }

    private List<Map<String, Object>> eventsFor(UUID executionId, int limit) {
        return jdbc.queryForList("""
                select event.*,
                       case when event.tool_digest is null then null
                            when allowlist.status='APPROVED' then 'APPROVED'
                            else 'UNDECLARED' end component_approval_state
                  from ai_agent_execution_events event
                  join ai_agent_executions execution on execution.id=event.execution_id
                  left join ai_grid_component_allowlists allowlist
                    on allowlist.provider=execution.provider and allowlist.component_kind='TOOL'
                   and allowlist.component_digest=event.tool_digest
                 where event.execution_id = :executionId
                 order by event.event_time, event.sequence, event.provider_event_digest nulls first
                 limit :limit
                """, new MapSqlParameterSource().addValue("executionId", executionId).addValue("limit", limit));
    }

    /**
     * Groups executions and computes the registered metric.
     *
     * <p>The grouping column and metric expressions are interpolated, but both are resolved from
     * the platform-owned runtime field registry and a closed metric vocabulary validated at package
     * import — never from request input.
     */
    private AggregateRead aggregateGroups(RuntimePolicy policy, String groupingColumn,
                                           String metric, Instant from, int maximumRows, int maximumEvents) {
        String measured = switch (metric) {
            case "RETRIES" -> "sum(s.retry_count)";
            case "TOKEN_TOTAL" -> "sum(s.token_count)";
            case "SPEND_MICROS" -> "sum(s.spend_micros)";
            case "LATENCY_MS" -> "max(s.latency_ms)";
            case "EVENT_COUNT" -> "coalesce(sum(c.event_count), 0)";
            case "REPEATED_ACTION_SIGNATURE" -> "coalesce(max(g.max_signature), 0)";
            default -> "null::numeric";
        };
        // A null contributor can only understate a sum or max, so it must block the comparison
        // rather than silently shrink the measured value.
        String nullContributors = switch (metric) {
            case "RETRIES" -> "count(*) filter (where s.retry_count is null)";
            case "TOKEN_TOTAL" -> "count(*) filter (where s.token_count is null)";
            case "SPEND_MICROS" -> "count(*) filter (where s.spend_micros is null)";
            case "LATENCY_MS" -> "count(*) filter (where s.latency_ms is null)";
            default -> "0";
        };
        List<UUID> executionIds = jdbc.queryForList("""
                select id from ai_agent_executions
                 where evidence_time >= :from
                   and %s is not null
                   and (:anyProvider or provider = :provider)
                 order by evidence_time desc, id
                 limit :limit
                """.formatted(groupingColumn), new MapSqlParameterSource()
                .addValue("from", Timestamp.from(from))
                .addValue("anyProvider", isAnyProvider(policy.provider()))
                .addValue("provider", policy.provider())
                .addValue("limit", maximumRows + 1), UUID.class);
        if (executionIds.size() > maximumRows) return new AggregateRead(List.of(), "maximumRowsExamined");
        if (executionIds.isEmpty()) return new AggregateRead(List.of(), null);
        List<UUID> eventIds = jdbc.queryForList("""
                select id from ai_agent_execution_events
                 where execution_id in (:executionIds)
                 order by event_time, sequence, id
                 limit :limit
                """, new MapSqlParameterSource().addValue("executionIds", executionIds)
                .addValue("limit", maximumEvents + 1), UUID.class);
        if (eventIds.size() > maximumEvents) return new AggregateRead(List.of(), "maximumEventsExamined");
        List<Map<String, Object>> groups = jdbc.queryForList("""
                with scoped as (
                    select e.id, e.%1$s group_value, e.evidence_time,
                           e.retry_count, e.token_count, e.spend_micros, e.latency_ms
                      from ai_agent_executions e
                     where e.id in (:executionIds)
                ), event_counts as (
                    select v.execution_id, count(*) event_count
                      from ai_agent_execution_events v
                      join scoped s on s.id = v.execution_id
                     group by v.execution_id
                ), signature_counts as (
                    select group_value, max(signature_count) max_signature
                      from (select s.group_value, v.action_correlation_digest, count(*) signature_count
                              from ai_agent_execution_events v
                              join scoped s on s.id = v.execution_id
                             where v.action_correlation_digest is not null
                             group by s.group_value, v.action_correlation_digest) repeated
                     group by group_value
                )
                select s.group_value,
                       count(*) examined_rows,
                       %2$s measured,
                       %3$s null_contributors,
                       (array_agg(s.id order by s.evidence_time desc, s.id))[1] anchor_execution_id,
                       max(s.evidence_time) anchor_evidence_time
                  from scoped s
                  left join event_counts c on c.execution_id = s.id
                  left join signature_counts g on g.group_value = s.group_value
                 group by s.group_value
                 order by s.group_value
                """.formatted(groupingColumn, measured, nullContributors), new MapSqlParameterSource()
                .addValue("executionIds", executionIds));
        return new AggregateRead(groups, null);
    }

    private static boolean isAnyProvider(String provider) {
        return provider == null || "ANY".equals(provider) || "MULTI_CLOUD".equals(provider);
    }

    // ---------------------------------------------------------------- persist

    /**
     * Records a policy-wide contract gap. The subject is the policy itself rather than any
     * execution, so an unsupported evidence family never fabricates per-execution assessments.
     */
    private boolean persistPolicyWide(Tenant tenant, UUID runId, Instant evaluationAsOf, RuntimePolicy policy,
                                      String selection, String decision, String reason,
                                      List<String> missing, Map<String, Object> evidence) {
        String scope = policy.id() + "|" + policy.provider();
        UUID subjectId = deterministicSubject("POLICY", scope);
        return persist(tenant, runId, evaluationAsOf, policy, selection, "POLICY", subjectId,
                findingFingerprint(tenant.getId(), policy.id(), "POLICY", scope),
                "NOT_APPLICABLE", "CAPABILITY_UNAVAILABLE", decision, reason, missing, evidence, false);
    }

    private boolean persistPolicyUnknown(Tenant tenant, UUID runId, Instant evaluationAsOf, RuntimePolicy policy,
                                         String selection, String reason, List<String> missing) {
        String scope = policy.id() + "|" + policy.provider();
        UUID subjectId = deterministicSubject("POLICY", scope);
        return persist(tenant, runId, evaluationAsOf, policy, selection, "POLICY", subjectId,
                findingFingerprint(tenant.getId(), policy.id(), "POLICY", scope),
                "APPLICABLE", "INCOMPLETE_EVIDENCE", "NO_DECISION", reason, missing, Map.of(), false);
    }

    private boolean persistExecution(Tenant tenant, UUID runId, Instant evaluationAsOf, RuntimePolicy policy,
                                     String selection, Candidate candidate, String dedupValue, String decision,
                                     String reason, List<String> missing, Map<String, Object> evidence,
                                     boolean reconcileFinding) {
        return persist(tenant, runId, evaluationAsOf, policy, selection, "EXECUTION", candidate.executionId(),
                findingFingerprint(tenant.getId(), policy.id(), "SEQUENCE", dedupValue),
                "APPLICABLE", readiness(decision), decision, reason, missing, evidence, reconcileFinding);
    }

    private boolean persistAggregate(Tenant tenant, UUID runId, Instant evaluationAsOf, RuntimePolicy policy,
                                     String selection, Candidate candidate, String groupValue, String decision,
                                     String reason, List<String> missing, Map<String, Object> evidence) {
        return persist(tenant, runId, evaluationAsOf, policy, selection, "EXECUTION", candidate.executionId(),
                findingFingerprint(tenant.getId(), policy.id(), "GROUP", groupValue),
                "APPLICABLE", readiness(decision), decision, reason, missing, evidence, true);
    }

    private boolean persist(Tenant tenant, UUID runId, Instant evaluationAsOf, RuntimePolicy policy,
                            String selection, String subjectType, UUID subjectId, String findingFingerprint,
                            String applicability, String readiness, String decision, String reason,
                            List<String> missing, Map<String, Object> evidence, boolean reconcileFinding) {
        UUID assessmentId = UUID.randomUUID();
        String decisionFingerprint = sha256(policy.version() + "|" + decision + "|" + reason
                + "|" + findingFingerprint);
        UUID persisted = jdbc.queryForObject("""
                insert into ai_grid_assessments (id, tenant_id, run_id, policy_id, policy_version,
                    subject_type, subject_id, snapshot_manifest_id, selection, applicability,
                    evidence_readiness, decision, reason_code, missing_evidence_json, input_facts_json,
                    fingerprint, evaluation_as_of, decision_fingerprint)
                values (:id, :tenantId, :runId, :policyId, :policyVersion, :subjectType, :subjectId,
                    null, :selection, :applicability, :readiness, :decision, :reason,
                    cast(:missing as jsonb), cast(:evidence as jsonb), :fingerprint,
                    :evaluationAsOf, :decisionFingerprint)
                on conflict (tenant_id, run_id, policy_id, subject_type, subject_id, fingerprint) do update set
                    policy_version = excluded.policy_version, selection = excluded.selection,
                    applicability = excluded.applicability, evidence_readiness = excluded.evidence_readiness,
                    decision = excluded.decision, reason_code = excluded.reason_code,
                    missing_evidence_json = excluded.missing_evidence_json,
                    input_facts_json = excluded.input_facts_json, fingerprint = excluded.fingerprint,
                    evaluation_as_of = excluded.evaluation_as_of,
                    decision_fingerprint = excluded.decision_fingerprint, evaluated_at = now()
                returning id
                """, new MapSqlParameterSource().addValue("id", assessmentId)
                .addValue("tenantId", tenant.getId()).addValue("runId", runId)
                .addValue("policyId", policy.id()).addValue("policyVersion", policy.version())
                .addValue("subjectType", subjectType).addValue("subjectId", subjectId)
                .addValue("selection", selection).addValue("applicability", applicability)
                .addValue("readiness", readiness).addValue("decision", decision).addValue("reason", reason)
                .addValue("missing", json(missing)).addValue("evidence", json(evidence))
                .addValue("fingerprint", findingFingerprint)
                .addValue("evaluationAsOf", Timestamp.from(evaluationAsOf))
                .addValue("decisionFingerprint", decisionFingerprint), UUID.class);
        snapshots.outbox(tenant, "ASSESSMENT_COMPLETED", "ASSESSMENT", persisted, decisionFingerprint,
                Map.of("decision", decision, "subjectId", subjectId, "decisionFingerprint", decisionFingerprint));
        if (!reconcileFinding) return false;
        return findings.reconcile(tenant, new AiGridFindingService.AssessmentResult(persisted, runId,
                policy.id(), policy.version(), policy.name(), policy.severity(), selection, decision, reason,
                subjectId, findingFingerprint, evidence, subjectType));
    }

    private static String readiness(String decision) {
        return "PASS".equals(decision) || "FAIL".equals(decision) ? "READY" : "INCOMPLETE_EVIDENCE";
    }

    private Map<String, Object> sequenceEvidence(RuntimePolicy policy, Candidate candidate,
                                                 SequenceOutcome outcome, List<Map<String, Object>> events,
                                                 Map<String, RuntimeField> registry) {
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("executionId", Map.of("value", candidate.executionId().toString()));
        evidence.put("deduplicationValue", Map.of("value", candidate.dedupValue()));
        evidence.put("eventsExamined", Map.of("value", events.size()));
        evidence.put("matchedEventIds", Map.of("value",
                outcome.matchedEventIds().stream().map(UUID::toString).toList()));
        if (outcome.firstMatch() != null) {
            evidence.put("sequenceStartedAt", Map.of("value", outcome.firstMatch().toString()));
            evidence.put("sequenceEndedAt", Map.of("value", outcome.lastMatch().toString()));
        }
        for (JsonNode field : policy.definition().path("runtimeSequence").path("explanationFields")) {
            RuntimeField resolved = registry.get(field.asText());
            if (resolved != null && "ai_agent_execution_events".equals(resolved.sourceTable())) {
                List<String> values = events.stream()
                        .filter(event -> outcome.matchedEventIds().contains(event.get("id")))
                        .map(event -> event.get(resolved.sourceColumn()))
                        .filter(java.util.Objects::nonNull).map(String::valueOf).distinct().toList();
                evidence.put("explanationField:" + field.asText(), Map.of("value", values));
            }
        }
        return evidence;
    }

    private static Set<String> values(JsonNode node) {
        if (node == null || node.isMissingNode() || node.isNull()) return Set.of();
        if (node.isArray()) {
            Set<String> result = new LinkedHashSet<>();
            node.forEach(value -> result.add(value.asText()));
            return result;
        }
        return Set.of(node.asText());
    }

    private JsonNode tree(String value) {
        try {
            return objectMapper.readTree(value == null || value.isBlank() ? "{}" : value);
        } catch (Exception error) {
            throw new IllegalArgumentException("Invalid runtime evaluation definition", error);
        }
    }

    private String json(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception error) {
            throw new IllegalArgumentException("Invalid runtime assessment JSON", error);
        }
    }

    /** Stable identity of a runtime finding: tenant + policy + deduplication or grouping scope. */
    static String findingFingerprint(UUID tenantId, String policyId, String scope, String scopeValue) {
        return sha256(tenantId + "|AI_RUNTIME|" + policyId + "|" + scope + "|" + scopeValue);
    }

    private static UUID deterministicSubject(String scope, String value) {
        return UUID.nameUUIDFromBytes((scope + "|" + value).getBytes(StandardCharsets.UTF_8));
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception error) {
            throw new IllegalStateException("Unable to fingerprint runtime assessment", error);
        }
    }

    record RuntimePolicy(String id, String version, String name, String severity, String provider,
                         String reasonCode, String evaluationMode, JsonNode definition,
                         String defaultSelection) {
        RuntimePolicy withProvider(String value) {
            return new RuntimePolicy(id, version, name, severity, value, reasonCode,
                    evaluationMode, definition, defaultSelection);
        }
    }
    record RuntimeField(String sourceTable, String sourceColumn, String valueType, boolean physicalColumn) { }
    private record FactCondition(String field, String column, String operator, Set<String> values) { }
    private record EventPredicate(String field, String column, String operator, Set<String> values,
                                  boolean unsupported) { }
    private record SequenceStep(List<EventPredicate> conditions) { }
    private record SequenceOutcome(boolean matched, String unpopulatedField, List<UUID> matchedEventIds,
                                   Instant firstMatch, Instant lastMatch) { }
    private record Candidate(UUID executionId, String dedupValue, Timestamp evidenceTime) { }
    private record AggregateRead(List<Map<String, Object>> groups, String boundReason) { }
}
