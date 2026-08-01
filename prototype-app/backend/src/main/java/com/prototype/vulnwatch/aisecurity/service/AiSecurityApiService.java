package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ReviewDisposition;
import com.prototype.vulnwatch.aisecurity.policy.AiSecurityPolicyRegistry;
import com.prototype.vulnwatch.aisecurity.policy.AiSecurityPolicyRegistry.PolicyDefinition;
import com.prototype.vulnwatch.aisecurity.policy.AiSecurityPolicyRegistry.PolicyParameterSpec;
import com.prototype.vulnwatch.aisecurity.policy.AiSecurityPolicyScopeMatcher;
import com.prototype.vulnwatch.aisecurity.policy.AiSecurityPolicyScopeMatcher.ArtifactScopeFacts;
import com.prototype.vulnwatch.aisecurity.policy.AiSecurityPolicyScopeMatcher.ScopeCondition;
import com.prototype.vulnwatch.aisecurity.policy.AiSecurityPolicyScopeMatcher.ScopeConfig;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AiSecurityApiService {

    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectMapper objectMapper;
    private final TenantSchemaExecutionService tenantExecution;
    private final TransactionTemplate transactionTemplate;
    private final AiSecurityPolicyRegistry policyRegistry;
    private final AiSecurityPolicyEvaluationService evaluationService;
    private final AiSecuritySyncRunFacade syncRunFacade;
    private final AuditEventService auditEventService;

    public AiSecurityApiService(
            NamedParameterJdbcTemplate jdbc,
            ObjectMapper objectMapper,
            TenantSchemaExecutionService tenantExecution,
            TransactionTemplate transactionTemplate,
            AiSecurityPolicyRegistry policyRegistry,
            AiSecurityPolicyEvaluationService evaluationService,
            AiSecuritySyncRunFacade syncRunFacade,
            AuditEventService auditEventService
    ) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
        this.tenantExecution = tenantExecution;
        this.transactionTemplate = transactionTemplate;
        this.policyRegistry = policyRegistry;
        this.evaluationService = evaluationService;
        this.syncRunFacade = syncRunFacade;
        this.auditEventService = auditEventService;
    }

    public SummaryResponse summary(Tenant tenant) {
        return tenantExecution.run(tenant, () -> {
            Map<String, Long> counts = jdbc.query("""
                    select artifact_type, count(*) as total
                      from ai_security_artifacts
                     where active = true
                     group by artifact_type
                    """, rs -> {
                Map<String, Long> result = new LinkedHashMap<>();
                while (rs.next()) {
                    result.put(rs.getString("artifact_type"), rs.getLong("total"));
                }
                return result;
            });
            long openFindings = count("select count(*) from ai_security_findings where status = 'OPEN'", Map.of());
            long incomplete = count("""
                    select count(*) from ai_security_snapshot_scopes
                     where status in ('PARTIAL','FAILED','UNSUPPORTED')
                    """, Map.of());
            Instant lastCompleted = jdbc.query("""
                    select max(completed_at) from ai_security_snapshot_scopes where status = 'COMPLETE'
                    """, rs -> rs.next() && rs.getTimestamp(1) != null ? rs.getTimestamp(1).toInstant() : null);
            return new SummaryResponse(counts, openFindings, incomplete, lastCompleted);
        });
    }

    public PageResponse<ArtifactResponse> artifacts(Tenant tenant, String artifactType, int page, int size) {
        return artifacts(tenant, artifactType, null, null, page, size);
    }

    public PageResponse<ArtifactResponse> artifacts(
            Tenant tenant,
            String artifactType,
            String provider,
            String subscription,
            int page,
            int size
    ) {
        int safePage = Math.max(0, page);
        int safeSize = Math.max(1, Math.min(100, size));
        return tenantExecution.run(tenant, () -> {
            MapSqlParameterSource params = new MapSqlParameterSource()
                    .addValue("artifactType", blankToNull(artifactType), Types.VARCHAR)
                    .addValue("otherArtifacts", "OTHER_AI_ARTIFACT".equalsIgnoreCase(artifactType), Types.BOOLEAN)
                    .addValue("provider", normalizedProvider(provider), Types.VARCHAR)
                    .addValue("subscription", blankToNull(subscription), Types.VARCHAR)
                    .addValue("limit", safeSize, Types.INTEGER)
                    .addValue("offset", safePage * safeSize, Types.INTEGER);
            List<ArtifactResponse> items = jdbc.query("""
                    select id, provider, provider_resource_id, artifact_type, native_kind, name,
                           account_id, region, active, attributes_json::text,
                           first_observed_at, last_observed_at
                      from ai_security_artifacts
                     where (:artifactType is null
                        or (:otherArtifacts = true and artifact_type not in ('AI_AGENT', 'AI_MODEL'))
                        or (:otherArtifacts = false and artifact_type = :artifactType))
                       and (:provider is null or provider = :provider)
                       and (:subscription is null or account_id = :subscription)
                     order by active desc, last_observed_at desc, id
                     limit :limit offset :offset
                    """, params, this::artifact);
            long total = count("""
                    select count(*) from ai_security_artifacts
                     where (:artifactType is null
                        or (:otherArtifacts = true and artifact_type not in ('AI_AGENT', 'AI_MODEL'))
                        or (:otherArtifacts = false and artifact_type = :artifactType))
                       and (:provider is null or provider = :provider)
                       and (:subscription is null or account_id = :subscription)
                    """, params);
            return new PageResponse<>(items, safePage, safeSize, total);
        });
    }

    public ArtifactResponse artifact(Tenant tenant, UUID artifactId) {
        return tenantExecution.run(tenant, () -> {
            List<ArtifactResponse> rows = jdbc.query("""
                    select id, provider, provider_resource_id, artifact_type, native_kind, name,
                           account_id, region, active, attributes_json::text,
                           first_observed_at, last_observed_at
                      from ai_security_artifacts where id = :id
                    """, Map.of("id", artifactId), this::artifact);
            if (rows.isEmpty()) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND, "AI Security artifact not found");
            }
            return rows.get(0);
        });
    }

    public List<RelationshipResponse> relationships(Tenant tenant, UUID artifactId) {
        return tenantExecution.run(tenant, () -> jdbc.query("""
                select r.id, r.relationship_type, r.source_artifact_id, source.name as source_name,
                       r.target_artifact_id, target.name as target_name, r.attributes_json::text
                  from ai_security_relationships r
                  join ai_security_artifacts source on source.id = r.source_artifact_id
                  join ai_security_artifacts target on target.id = r.target_artifact_id
                 where r.active = true
                   and (r.source_artifact_id = :id or r.target_artifact_id = :id)
                 order by r.relationship_type, r.id
                 limit 1000
                """, Map.of("id", artifactId), (rs, rowNum) -> new RelationshipResponse(
                rs.getObject("id", UUID.class),
                rs.getString("relationship_type"),
                rs.getObject("source_artifact_id", UUID.class),
                rs.getString("source_name"),
                rs.getObject("target_artifact_id", UUID.class),
                rs.getString("target_name"),
                readMap(rs.getString("attributes_json")))));
    }

    public GraphResponse graph(Tenant tenant, UUID rootArtifactId) {
        return tenantExecution.run(tenant, () -> {
            List<ArtifactResponse> nodes;
            List<RelationshipResponse> edges;
            if (rootArtifactId == null) {
                nodes = jdbc.query("""
                        select id, provider, provider_resource_id, artifact_type, native_kind, name,
                               account_id, region, active, attributes_json::text,
                               first_observed_at, last_observed_at
                          from ai_security_artifacts where active = true
                         order by last_observed_at desc limit 500
                        """, this::artifact);
                edges = graphEdges(null, 1001);
            } else {
                artifact(tenant, rootArtifactId);
                edges = graphEdges(rootArtifactId, 1001);
                java.util.LinkedHashSet<UUID> ids = new java.util.LinkedHashSet<>();
                ids.add(rootArtifactId);
                edges.forEach(edge -> {
                    ids.add(edge.sourceArtifactId());
                    ids.add(edge.targetArtifactId());
                });
                nodes = ids.stream().limit(500).map(id -> artifact(tenant, id)).toList();
            }
            boolean truncated = nodes.size() >= 500 || edges.size() > 1000;
            return new GraphResponse(nodes.stream().limit(500).toList(), edges.stream().limit(1000).toList(), truncated);
        });
    }

    public PageResponse<FindingResponse> findings(Tenant tenant, String policyId, String status, int page, int size) {
        return findings(tenant, policyId, status, null, null, page, size);
    }

    public PageResponse<FindingResponse> findings(
            Tenant tenant,
            String policyId,
            String status,
            String provider,
            String subscription,
            int page,
            int size
    ) {
        int safePage = Math.max(0, page);
        int safeSize = Math.max(1, Math.min(100, size));
        return tenantExecution.run(tenant, () -> {
            MapSqlParameterSource params = new MapSqlParameterSource()
                    .addValue("policyId", blankToNull(policyId), Types.VARCHAR)
                    .addValue("status", blankToNull(status), Types.VARCHAR)
                    .addValue("provider", normalizedProvider(provider), Types.VARCHAR)
                    .addValue("subscription", blankToNull(subscription), Types.VARCHAR)
                    .addValue("limit", safeSize, Types.INTEGER)
                    .addValue("offset", safePage * safeSize, Types.INTEGER);
            String filter = """
                     where (:policyId is null or f.policy_id = :policyId)
                       and (:status is null or f.status = :status)
                       and (:provider is null or a.provider = :provider)
                       and (:subscription is null or a.account_id = :subscription)
                    """;
            List<FindingResponse> items = jdbc.query("""
                    select f.id, f.display_id, f.policy_id, f.policy_version, f.artifact_id,
                           a.name as artifact_name, f.severity, f.status, f.title,
                           f.evidence_json::text, f.first_observed_at, f.last_observed_at, f.resolved_at,
                           coalesce(review.disposition, 'UNREVIEWED') as disposition
                      from ai_security_findings f
                      join ai_security_artifacts a on a.id = f.artifact_id
                      left join lateral (
                          select disposition from ai_security_finding_reviews r
                           where r.finding_id = f.id order by reviewed_at desc limit 1
                      ) review on true
                    """ + filter + " order by f.last_observed_at desc, f.id limit :limit offset :offset",
                    params, this::finding);
            long total = count("""
                    select count(*) from ai_security_findings f
                    join ai_security_artifacts a on a.id = f.artifact_id
                    """ + filter, params);
            return new PageResponse<>(items, safePage, safeSize, total);
        });
    }

    public FindingResponse finding(Tenant tenant, UUID findingId) {
        return tenantExecution.run(tenant, () -> findingsById(findingId).stream().findFirst()
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "AI Security finding not found")));
    }

    public FindingResponse review(
            Tenant tenant, UUID findingId, ReviewDisposition disposition, String reason, String actor) {
        if (disposition == null || disposition == ReviewDisposition.UNREVIEWED) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "A review disposition is required");
        }
        return tenantExecution.run(tenant, () -> transactionTemplate.execute(status -> {
            FindingResponse finding = findingsById(findingId).stream().findFirst()
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "AI Security finding not found"));
            jdbc.update("""
                    insert into ai_security_finding_reviews (
                        id, tenant_id, finding_id, disposition, reason, policy_version, reviewed_by
                    ) values (
                        :id, :tenantId, :findingId, :disposition, :reason, :policyVersion, :reviewedBy
                    )
                    """, new MapSqlParameterSource()
                    .addValue("id", UUID.randomUUID())
                    .addValue("tenantId", tenant.getId())
                    .addValue("findingId", findingId)
                    .addValue("disposition", disposition.name())
                    .addValue("reason", blankToNull(reason))
                    .addValue("policyVersion", finding.policyVersion())
                    .addValue("reviewedBy", actor));
            auditEventService.record("ai_security.finding.reviewed", "ai_security_finding",
                    findingId.toString(), "{\"disposition\":\"" + disposition.name() + "\"}");
            return findingsById(findingId).get(0);
        }));
    }

    public List<PolicyResponse> policies(Tenant tenant) {
        return tenantExecution.run(tenant, () -> policyRegistry.all().stream()
                .map(this::policy)
                .filter(PolicyResponse::available)
                .toList());
    }

    public PolicyResponse policy(Tenant tenant, String policyId) {
        return tenantExecution.run(tenant, () -> policyRegistry.find(policyId)
                .map(this::policy)
                .filter(PolicyResponse::available)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "AI Security policy not found")));
    }

    public PolicyResponse updatePolicy(Tenant tenant, String policyId, boolean enabled, String actor) {
        PolicyDefinition definition = policyRegistry.find(policyId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "AI Security policy not found"));
        return tenantExecution.run(tenant, () -> transactionTemplate.execute(status -> {
            if (!policy(definition).available()) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND, "AI Security policy not found");
            }
            jdbc.update("""
                    insert into ai_security_policy_settings (policy_id, tenant_id, enabled, updated_by)
                    values (:policyId, :tenantId, :enabled, :actor)
                    on conflict (policy_id) do update
                        set enabled = excluded.enabled, updated_by = excluded.updated_by, updated_at = now()
                    """, Map.of("policyId", policyId, "tenantId", tenant.getId(), "enabled", enabled, "actor", actor));
            if (!enabled) {
                jdbc.update("""
                        update ai_security_findings
                           set status = 'SUPPRESSED_BY_POLICY', last_observed_at = now()
                         where policy_id = :policyId and status = 'OPEN'
                        """, Map.of("policyId", policyId));
            } else {
                UUID latestRun = jdbc.query("""
                        select run_id from ai_security_snapshot_scopes
                         order by started_at desc limit 1
                        """, rs -> rs.next() ? rs.getObject("run_id", UUID.class) : null);
                if (latestRun != null) {
                    evaluationService.evaluateRunCurrentTenant(tenant, latestRun);
                }
            }
            auditEventService.record("ai_security.policy.updated", "ai_security_policy",
                    policyId, "{\"enabled\":" + enabled + "}");
            return policy(definition);
        }));
    }

    private static final Set<String> VALID_SCOPE_MODES = Set.of(
            AiSecurityPolicyScopeMatcher.MODE_ALL,
            AiSecurityPolicyScopeMatcher.MODE_MATCH_RULES,
            AiSecurityPolicyScopeMatcher.MODE_CUSTOM_LIST);
    private static final Set<String> VALID_SCOPE_FIELDS =
            Set.of("PROVIDER", "REGION", "ACCOUNT_ID", "ARTIFACT_TYPE", "NATIVE_KIND", "NAME");
    private static final Set<String> VALID_SCOPE_OPERATORS =
            Set.of("EQUALS", "NOT_EQUALS", "CONTAINS", "NOT_CONTAINS");
    private static final Set<String> VALID_OVERRIDES = Set.of(
            AiSecurityPolicyScopeMatcher.OVERRIDE_INCLUDED, AiSecurityPolicyScopeMatcher.OVERRIDE_EXCLUDED);
    private static final Set<String> STOP_TOKENS =
            Set.of("agent", "bot", "the", "and", "for", "test", "prod", "svc", "service");

    public PolicyConfigurationResponse policyConfiguration(Tenant tenant, String policyId) {
        PolicyDefinition definition = requirePolicy(policyId);
        return tenantExecution.run(tenant, () -> buildConfiguration(definition));
    }

    public PolicyConfigurationResponse updatePolicyScope(
            Tenant tenant, String policyId, String rawMode, String rawConditionLogic,
            List<PolicyScopeConditionResponse> rawConditions, String actor) {
        PolicyDefinition definition = requirePolicy(policyId);
        String mode = rawMode == null ? null : rawMode.toUpperCase(Locale.ROOT);
        if (!VALID_SCOPE_MODES.contains(mode)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unsupported scope mode");
        }
        String conditionLogic = "OR".equalsIgnoreCase(rawConditionLogic) ? "OR" : "AND";
        List<PolicyScopeConditionResponse> conditions = rawConditions == null ? List.of() : rawConditions;
        for (PolicyScopeConditionResponse condition : conditions) {
            if (!VALID_SCOPE_FIELDS.contains(condition.field())
                    || !VALID_SCOPE_OPERATORS.contains(condition.operator())) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unsupported scope condition");
            }
        }
        return tenantExecution.run(tenant, () -> transactionTemplate.execute(status -> {
            jdbc.update("""
                    insert into ai_security_policy_scopes (
                        policy_id, tenant_id, mode, condition_logic, conditions_json, updated_by
                    ) values (
                        :policyId, :tenantId, :mode, :conditionLogic, cast(:conditions as jsonb), :actor
                    ) on conflict (policy_id) do update
                        set mode = excluded.mode,
                            condition_logic = excluded.condition_logic,
                            conditions_json = excluded.conditions_json,
                            updated_by = excluded.updated_by,
                            updated_at = now()
                    """, new MapSqlParameterSource()
                    .addValue("policyId", policyId)
                    .addValue("tenantId", tenant.getId())
                    .addValue("mode", mode)
                    .addValue("conditionLogic", conditionLogic)
                    .addValue("conditions", json(conditions))
                    .addValue("actor", actor));
            auditEventService.record("ai_security.policy.scope_updated", "ai_security_policy", policyId,
                    "{\"mode\":\"" + mode + "\"}");
            evaluationService.reevaluatePolicy(tenant, policyId);
            return buildConfiguration(definition);
        }));
    }

    public PolicyConfigurationResponse addPolicyException(
            Tenant tenant, String policyId, UUID artifactId, String rawOverride, String reason, String actor) {
        PolicyDefinition definition = requirePolicy(policyId);
        if (artifactId == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "An artifact is required");
        }
        String override = rawOverride == null ? null : rawOverride.toUpperCase(Locale.ROOT);
        if (!VALID_OVERRIDES.contains(override)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unsupported exception override");
        }
        return tenantExecution.run(tenant, () -> transactionTemplate.execute(status -> {
            jdbc.update("""
                    insert into ai_security_policy_artifact_overrides (
                        id, tenant_id, policy_id, artifact_id, override, reason, created_by
                    ) values (
                        :id, :tenantId, :policyId, :artifactId, :override, :reason, :actor
                    ) on conflict (tenant_id, policy_id, artifact_id) do update
                        set override = excluded.override, reason = excluded.reason, updated_at = now()
                    """, new MapSqlParameterSource()
                    .addValue("id", UUID.randomUUID())
                    .addValue("tenantId", tenant.getId())
                    .addValue("policyId", policyId)
                    .addValue("artifactId", artifactId)
                    .addValue("override", override)
                    .addValue("reason", blankToNull(reason))
                    .addValue("actor", actor));
            auditEventService.record("ai_security.policy.exception_added", "ai_security_policy", policyId,
                    "{\"artifactId\":\"" + artifactId + "\",\"override\":\"" + override + "\"}");
            evaluationService.reevaluatePolicy(tenant, policyId);
            return buildConfiguration(definition);
        }));
    }

    public PolicyConfigurationResponse removePolicyException(
            Tenant tenant, String policyId, UUID artifactId, String actor) {
        PolicyDefinition definition = requirePolicy(policyId);
        return tenantExecution.run(tenant, () -> transactionTemplate.execute(status -> {
            jdbc.update("""
                    delete from ai_security_policy_artifact_overrides
                     where policy_id = :policyId and artifact_id = :artifactId
                    """, Map.of("policyId", policyId, "artifactId", artifactId));
            auditEventService.record("ai_security.policy.exception_removed", "ai_security_policy", policyId,
                    "{\"artifactId\":\"" + artifactId + "\"}");
            evaluationService.reevaluatePolicy(tenant, policyId);
            return buildConfiguration(definition);
        }));
    }

    public PolicyConfigurationResponse updatePolicyParameters(
            Tenant tenant, String policyId, Map<String, String> parameters, String actor) {
        PolicyDefinition definition = requirePolicy(policyId);
        List<PolicyParameterSpec> specs = policyRegistry.parameterSpecs(policyId);
        Map<String, String> validated = new LinkedHashMap<>();
        for (PolicyParameterSpec spec : specs) {
            String value = parameters == null ? null : parameters.get(spec.key());
            if (value == null || value.isBlank()) {
                validated.put(spec.key(), spec.defaultValue());
                continue;
            }
            if ("ENUM".equals(spec.type()) && !spec.options().contains(value.toUpperCase(Locale.ROOT))) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "Unsupported value for parameter " + spec.key());
            }
            validated.put(spec.key(), value.toUpperCase(Locale.ROOT));
        }
        return tenantExecution.run(tenant, () -> transactionTemplate.execute(status -> {
            jdbc.update("""
                    insert into ai_security_policy_parameters (policy_id, tenant_id, parameters_json, updated_by)
                    values (:policyId, :tenantId, cast(:parameters as jsonb), :actor)
                    on conflict (policy_id) do update
                        set parameters_json = excluded.parameters_json,
                            updated_by = excluded.updated_by,
                            updated_at = now()
                    """, new MapSqlParameterSource()
                    .addValue("policyId", policyId)
                    .addValue("tenantId", tenant.getId())
                    .addValue("parameters", json(validated))
                    .addValue("actor", actor));
            auditEventService.record("ai_security.policy.parameters_updated", "ai_security_policy", policyId,
                    json(validated));
            evaluationService.reevaluatePolicy(tenant, policyId);
            return buildConfiguration(definition);
        }));
    }

    public PolicyAssistExplanationResponse explainPolicy(Tenant tenant, String policyId) {
        PolicyDefinition definition = requirePolicy(policyId);
        return tenantExecution.run(tenant, () -> {
            PolicyConfigurationResponse configuration = buildConfiguration(definition);
            long openOnMatched = count("""
                    select count(*) from ai_security_findings where policy_id = :policyId and status = 'OPEN'
                    """, Map.of("policyId", policyId));
            StringBuilder text = new StringBuilder();
            if (configuration.totalArtifactCount() == 0) {
                text.append("No ").append(String.join(" or ", definition.artifactTypes()))
                        .append(" artifacts have been discovered yet, so this policy has nothing to evaluate.");
            } else if (configuration.matchedArtifactCount() == 0) {
                text.append("The current scope excludes all ").append(configuration.totalArtifactCount())
                        .append(" eligible artifact(s) in your inventory — this policy will not produce findings until scope is widened.");
            } else {
                text.append(configuration.matchedArtifactCount()).append(" of ")
                        .append(configuration.totalArtifactCount())
                        .append(" eligible artifact(s) are currently in scope for this policy. ");
                if (openOnMatched == 0) {
                    text.append("None of them currently violate it.");
                } else {
                    text.append(openOnMatched).append(" of them currently violate it and have an open finding.");
                }
                if (!configuration.parameters().isEmpty()) {
                    PolicyParameterValueResponse param = configuration.parameters().get(0);
                    text.append(" The policy is evaluated against your configured \"")
                            .append(param.label()).append("\" of ").append(param.value()).append(".");
                }
            }
            if (!configuration.exceptions().isEmpty()) {
                long excludedCount = configuration.exceptions().stream()
                        .filter(exception -> AiSecurityPolicyScopeMatcher.OVERRIDE_EXCLUDED.equals(exception.override()))
                        .count();
                if (excludedCount > 0) {
                    text.append(" ").append(excludedCount).append(" artifact(s) are explicitly excepted from this policy.");
                }
            }
            return new PolicyAssistExplanationResponse(text.toString(), Instant.now());
        });
    }

    public PolicyAssistScopeSuggestionResponse suggestScopeFromReviewHistory(Tenant tenant, String policyId) {
        requirePolicy(policyId);
        return tenantExecution.run(tenant, () -> {
            List<String> falsePositiveNames = jdbc.query("""
                    select distinct a.name
                      from ai_security_findings f
                      join ai_security_artifacts a on a.id = f.artifact_id
                      join lateral (
                          select disposition from ai_security_finding_reviews r
                           where r.finding_id = f.id order by reviewed_at desc limit 1
                      ) review on true
                     where f.policy_id = :policyId and review.disposition = 'FALSE_POSITIVE'
                    """, Map.of("policyId", policyId), (rs, rowNum) -> rs.getString("name"));

            if (falsePositiveNames.size() < 2) {
                return new PolicyAssistScopeSuggestionResponse(
                        null, "Not enough reviewed false positives yet to suggest a rule.", falsePositiveNames.size());
            }
            Map<String, Long> tokenCounts = new LinkedHashMap<>();
            for (String name : falsePositiveNames) {
                Set<String> tokensInName = Set.of(name.toLowerCase(Locale.ROOT).split("[^a-z0-9]+"));
                for (String token : tokensInName) {
                    if (token.length() < 3 || STOP_TOKENS.contains(token)) {
                        continue;
                    }
                    tokenCounts.merge(token, 1L, Long::sum);
                }
            }
            String bestToken = tokenCounts.entrySet().stream()
                    .filter(entry -> entry.getValue() >= 2)
                    .max(Map.Entry.comparingByValue())
                    .map(Map.Entry::getKey)
                    .orElse(null);
            if (bestToken == null) {
                return new PolicyAssistScopeSuggestionResponse(
                        null, "False positives so far don't share a common naming pattern.", falsePositiveNames.size());
            }
            PolicyScopeConditionResponse suggestion =
                    new PolicyScopeConditionResponse("NAME", "NOT_CONTAINS", bestToken);
            String rationale = tokenCounts.get(bestToken) + " of " + falsePositiveNames.size()
                    + " false-positive reviews on this policy were on artifacts named like \"" + bestToken + "\".";
            return new PolicyAssistScopeSuggestionResponse(suggestion, rationale, falsePositiveNames.size());
        });
    }

    private PolicyDefinition requirePolicy(String policyId) {
        return policyRegistry.find(policyId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "AI Security policy not found"));
    }

    private PolicyConfigurationResponse buildConfiguration(PolicyDefinition definition) {
        Map<String, Object> scopeRow = jdbc.query("""
                select mode, condition_logic, conditions_json::text, updated_by, updated_at
                  from ai_security_policy_scopes where policy_id = :policyId
                """, Map.of("policyId", definition.id()), rs -> rs.next()
                ? Map.of(
                        "mode", rs.getString("mode"),
                        "conditionLogic", rs.getString("condition_logic"),
                        "conditionsJson", rs.getString("conditions_json"),
                        "updatedBy", (Object) rs.getString("updated_by"),
                        "updatedAt", (Object) rs.getTimestamp("updated_at"))
                : Map.of());
        String mode = (String) scopeRow.getOrDefault("mode", AiSecurityPolicyScopeMatcher.MODE_ALL);
        String conditionLogic = (String) scopeRow.getOrDefault("conditionLogic", "AND");
        List<PolicyScopeConditionResponse> conditions = readConditions((String) scopeRow.get("conditionsJson"));
        PolicyScopeResponse scope = new PolicyScopeResponse(
                mode, conditionLogic, conditions,
                (String) scopeRow.get("updatedBy"),
                scopeRow.get("updatedAt") instanceof java.sql.Timestamp timestamp ? timestamp.toInstant() : null);

        List<PolicyExceptionResponse> exceptions = jdbc.query("""
                select o.artifact_id, a.name as artifact_name, o.override, o.reason, o.created_by, o.created_at
                  from ai_security_policy_artifact_overrides o
                  join ai_security_artifacts a on a.id = o.artifact_id
                 where o.policy_id = :policyId
                 order by o.created_at desc
                """, Map.of("policyId", definition.id()), (rs, rowNum) -> new PolicyExceptionResponse(
                rs.getObject("artifact_id", UUID.class),
                rs.getString("artifact_name"),
                rs.getString("override"),
                rs.getString("reason"),
                rs.getString("created_by"),
                instant(rs, "created_at")));
        Map<String, String> overridesByArtifact = new LinkedHashMap<>();
        exceptions.forEach(exception -> overridesByArtifact.put(exception.artifactId().toString(), exception.override()));

        List<ArtifactScopeRow> artifacts = jdbc.query("""
                select id, provider, region, account_id, artifact_type, native_kind, name
                  from ai_security_artifacts
                 where active = true and artifact_type in (:types)
                """, Map.of("types", definition.artifactTypes()),
                (rs, rowNum) -> new ArtifactScopeRow(
                        rs.getObject("id", UUID.class), rs.getString("provider"), rs.getString("region"),
                        rs.getString("account_id"), rs.getString("artifact_type"), rs.getString("native_kind"),
                        rs.getString("name")));
        ScopeConfig scopeConfig = new ScopeConfig(mode, conditionLogic, conditions.stream()
                .map(condition -> new ScopeCondition(condition.field(), condition.operator(), condition.value()))
                .toList());
        long matched = artifacts.stream()
                .filter(artifact -> AiSecurityPolicyScopeMatcher.isInScope(
                        scopeConfig,
                        new ArtifactScopeFacts(artifact.provider(), artifact.region(), artifact.accountId(),
                                artifact.artifactType(), artifact.nativeKind(), artifact.name()),
                        overridesByArtifact.get(artifact.id().toString())))
                .count();

        List<PolicyParameterValueResponse> parameters = buildParameterValues(definition.id());
        return new PolicyConfigurationResponse(scope, exceptions, parameters, matched, artifacts.size());
    }

    private List<PolicyParameterValueResponse> buildParameterValues(String policyId) {
        List<PolicyParameterSpec> specs = policyRegistry.parameterSpecs(policyId);
        if (specs.isEmpty()) {
            return List.of();
        }
        Map<String, Object> stored = jdbc.query("""
                select parameters_json::text from ai_security_policy_parameters where policy_id = :policyId
                """, Map.of("policyId", policyId), rs -> rs.next() ? readMap(rs.getString("parameters_json")) : Map.of());
        return specs.stream()
                .map(spec -> new PolicyParameterValueResponse(
                        spec.key(), spec.label(), spec.type(), spec.options(), spec.defaultValue(), spec.helpText(),
                        String.valueOf(stored.getOrDefault(spec.key(), spec.defaultValue()))))
                .toList();
    }

    @SuppressWarnings("unchecked")
    private List<PolicyScopeConditionResponse> readConditions(String conditionsJson) {
        if (conditionsJson == null || conditionsJson.isBlank()) {
            return List.of();
        }
        List<Map<String, Object>> raw;
        try {
            raw = objectMapper.readValue(conditionsJson, new com.fasterxml.jackson.core.type.TypeReference<>() {});
        } catch (Exception ex) {
            return List.of();
        }
        return raw.stream()
                .map(row -> new PolicyScopeConditionResponse(
                        String.valueOf(row.get("field")), String.valueOf(row.get("operator")), String.valueOf(row.get("value"))))
                .toList();
    }

    private record ArtifactScopeRow(
            UUID id, String provider, String region, String accountId, String artifactType, String nativeKind, String name) {
    }

    public List<RunResponse> runs(Tenant tenant) {
        return runs(tenant, null);
    }

    public List<RunResponse> runs(Tenant tenant, String provider) {
        String normalized = normalizedProvider(provider);
        return syncRunFacade.listForTenant(tenant.getId()).stream()
                .filter(run -> normalized == null
                        || ("AWS".equals(normalized)
                                && AiSecuritySyncRunFacade.AWS_SYNC_TYPE.equals(run.getSyncType()))
                        || ("AZURE".equals(normalized)
                                && AiSecuritySyncRunFacade.AZURE_SYNC_TYPE.equals(run.getSyncType())))
                .map(this::run)
                .toList();
    }

    public List<ScopeResponse> scopes(Tenant tenant, UUID runId) {
        return scopes(tenant, runId, null, null);
    }

    public List<ScopeResponse> scopes(Tenant tenant, UUID runId, String resourceFamily, String status) {
        syncRunFacade.loadForTenant(tenant.getId(), runId);
        return tenantExecution.run(tenant, () -> jdbc.query("""
                select id, run_id, account_id, region, resource_family, scope_key, status,
                       expected_chunks, accepted_chunks, diagnostic_code, diagnostic_json::text,
                       started_at, completed_at
                  from ai_security_snapshot_scopes
                 where run_id = :runId
                   and (:resourceFamily is null or resource_family = :resourceFamily)
                   and (:status is null or status = :status)
                 order by account_id, region, resource_family
                """, new MapSqlParameterSource()
                .addValue("runId", runId)
                .addValue("resourceFamily", blankToNull(resourceFamily))
                .addValue("status", blankToNull(status)), (rs, rowNum) -> new ScopeResponse(
                rs.getObject("id", UUID.class),
                rs.getObject("run_id", UUID.class),
                rs.getString("account_id"),
                rs.getString("region"),
                rs.getString("resource_family"),
                rs.getString("scope_key"),
                rs.getString("status"),
                rs.getInt("accepted_chunks"),
                rs.getInt("expected_chunks"),
                rs.getString("diagnostic_code"),
                readMap(rs.getString("diagnostic_json")),
                instant(rs, "started_at"),
                instant(rs, "completed_at"))));
    }

    private String normalizedProvider(String provider) {
        String value = blankToNull(provider);
        if (value == null) return null;
        String normalized = value.toUpperCase(java.util.Locale.ROOT);
        if (!List.of("AWS", "AZURE").contains(normalized)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unsupported AI Security provider");
        }
        return normalized;
    }

    private PolicyResponse policy(PolicyDefinition definition) {
        Map<String, Object> row = jdbc.queryForMap("""
                select d.available, d.default_enabled, s.enabled as tenant_enabled,
                       coalesce(open_counts.open_count, 0) as open_count,
                       coalesce(lifetime_counts.lifetime_count, 0) as lifetime_count,
                       quality.last_evaluated_at, quality.pass_count, quality.fail_count,
                       quality.no_decision_count
                  from platform.ai_security_policy_distribution d
                  left join ai_security_policy_settings s on s.policy_id = d.policy_id
                  left join (
                      select policy_id, count(*) as open_count from ai_security_findings
                       where status = 'OPEN' group by policy_id
                  ) open_counts on open_counts.policy_id = d.policy_id
                  left join (
                      select policy_id, count(*) as lifetime_count from ai_security_findings group by policy_id
                  ) lifetime_counts on lifetime_counts.policy_id = d.policy_id
                  left join (
                      select policy_id, max(evaluated_at) as last_evaluated_at,
                             count(*) filter (where outcome = 'PASS') as pass_count,
                             count(*) filter (where outcome = 'FAIL') as fail_count,
                             count(*) filter (where outcome = 'NO_DECISION') as no_decision_count
                        from ai_security_policy_evaluations group by policy_id
                  ) quality on quality.policy_id = d.policy_id
                 where d.policy_id = :policyId
                """, Map.of("policyId", definition.id()));
        boolean available = Boolean.TRUE.equals(row.get("available"));
        Boolean tenantEnabled = (Boolean) row.get("tenant_enabled");
        boolean enabled = available && (tenantEnabled != null
                ? tenantEnabled
                : Boolean.TRUE.equals(row.get("default_enabled")));
        long pass = number(row.get("pass_count"));
        long fail = number(row.get("fail_count"));
        long noDecision = number(row.get("no_decision_count"));
        CoverageGate coverageGate = coverageGate(definition.severity(), pass, fail, noDecision);
        return new PolicyResponse(
                definition.id(), definition.version(), definition.name(), definition.severity(),
                definition.artifactTypes(), definition.requiredResourceFamilies(), definition.description(),
                definition.remediation(), definition.controlMappings(), available, enabled,
                number(row.get("open_count")), number(row.get("lifetime_count")),
                row.get("last_evaluated_at") instanceof java.sql.Timestamp timestamp ? timestamp.toInstant() : null,
                coverageGate.coverage(), coverageGate.threshold(), coverageGate.status(),
                coverageGate.evaluatedArtifacts(), coverageGate.noDecisionCount());
    }

    static CoverageGate coverageGate(String severity, long pass, long fail, long noDecision) {
        long evaluated = pass + fail + noDecision;
        double coverage = evaluated == 0 ? 0 : ((double) (pass + fail) / evaluated);
        double threshold = "CRITICAL".equals(severity) ? 1.0 : 0.95;
        String status = evaluated == 0 ? "NO_DATA" : coverage >= threshold ? "PASS" : "FAIL";
        return new CoverageGate(coverage, threshold, status, evaluated, noDecision);
    }

    private List<FindingResponse> findingsById(UUID findingId) {
        return jdbc.query("""
                select f.id, f.display_id, f.policy_id, f.policy_version, f.artifact_id,
                       a.name as artifact_name, f.severity, f.status, f.title,
                       f.evidence_json::text, f.first_observed_at, f.last_observed_at, f.resolved_at,
                       coalesce(review.disposition, 'UNREVIEWED') as disposition
                  from ai_security_findings f
                  join ai_security_artifacts a on a.id = f.artifact_id
                  left join lateral (
                      select disposition from ai_security_finding_reviews r
                       where r.finding_id = f.id order by reviewed_at desc limit 1
                  ) review on true
                 where f.id = :id
                """, Map.of("id", findingId), this::finding);
    }

    private List<RelationshipResponse> graphEdges(UUID root, int limit) {
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("root", root)
                .addValue("limit", limit);
        return jdbc.query("""
                select r.id, r.relationship_type, r.source_artifact_id, source.name as source_name,
                       r.target_artifact_id, target.name as target_name, r.attributes_json::text
                  from ai_security_relationships r
                  join ai_security_artifacts source on source.id = r.source_artifact_id
                  join ai_security_artifacts target on target.id = r.target_artifact_id
                 where r.active = true
                   and (:root is null or r.source_artifact_id = :root or r.target_artifact_id = :root)
                 order by r.last_observed_at desc limit :limit
                """, params, (rs, rowNum) -> new RelationshipResponse(
                rs.getObject("id", UUID.class),
                rs.getString("relationship_type"),
                rs.getObject("source_artifact_id", UUID.class),
                rs.getString("source_name"),
                rs.getObject("target_artifact_id", UUID.class),
                rs.getString("target_name"),
                readMap(rs.getString("attributes_json"))));
    }

    private ArtifactResponse artifact(ResultSet rs, int rowNum) throws SQLException {
        return new ArtifactResponse(
                rs.getObject("id", UUID.class),
                rs.getString("provider"),
                rs.getString("provider_resource_id"),
                rs.getString("artifact_type"),
                rs.getString("native_kind"),
                rs.getString("name"),
                rs.getString("account_id"),
                rs.getString("region"),
                rs.getBoolean("active"),
                readMap(rs.getString("attributes_json")),
                instant(rs, "first_observed_at"),
                instant(rs, "last_observed_at"));
    }

    private FindingResponse finding(ResultSet rs, int rowNum) throws SQLException {
        return new FindingResponse(
                rs.getObject("id", UUID.class),
                rs.getString("display_id"),
                rs.getString("policy_id"),
                rs.getString("policy_version"),
                rs.getObject("artifact_id", UUID.class),
                rs.getString("artifact_name"),
                rs.getString("severity"),
                rs.getString("status"),
                rs.getString("title"),
                readMap(rs.getString("evidence_json")),
                rs.getString("disposition"),
                instant(rs, "first_observed_at"),
                instant(rs, "last_observed_at"),
                instant(rs, "resolved_at"));
    }

    private RunResponse run(SyncRun run) {
        return new RunResponse(
                run.getId(), run.getStatus(), run.getRecordsFetched(), run.getRecordsFailed(),
                run.getStartedAt(), run.getCompletedAt(), run.getErrorMessage());
    }

    private long count(String sql, org.springframework.jdbc.core.namedparam.SqlParameterSource params) {
        Long value = jdbc.queryForObject(sql, params, Long.class);
        return value == null ? 0 : value;
    }

    private long count(String sql, Map<String, ?> params) {
        Long value = jdbc.queryForObject(sql, params, Long.class);
        return value == null ? 0 : value;
    }

    private long number(Object value) {
        return value instanceof Number number ? number.longValue() : 0;
    }

    private Map<String, Object> readMap(String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            return objectMapper.readValue(json, new TypeReference<>() {});
        } catch (Exception ex) {
            return Map.of();
        }
    }

    private String json(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception ex) {
            throw new IllegalArgumentException("Unable to serialize AI Security payload", ex);
        }
    }

    private String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private Instant instant(ResultSet rs, String column) throws SQLException {
        return rs.getTimestamp(column) == null ? null : rs.getTimestamp(column).toInstant();
    }

    public record SummaryResponse(
            Map<String, Long> artifactCounts,
            long openFindings,
            long incompleteScopes,
            Instant lastCompleteSnapshotAt
    ) {
    }

    public record PageResponse<T>(List<T> items, int page, int size, long total) {
    }

    public record ArtifactResponse(
            UUID id, String provider, String providerResourceId, String artifactType, String nativeKind,
            String name, String accountId, String region, boolean active, Map<String, Object> attributes,
            Instant firstObservedAt, Instant lastObservedAt
    ) {
    }

    public record RelationshipResponse(
            UUID id, String relationshipType, UUID sourceArtifactId, String sourceName,
            UUID targetArtifactId, String targetName, Map<String, Object> attributes
    ) {
    }

    public record GraphResponse(
            List<ArtifactResponse> nodes,
            List<RelationshipResponse> edges,
            boolean truncated
    ) {
    }

    public record FindingResponse(
            UUID id, String displayId, String policyId, String policyVersion, UUID artifactId,
            String artifactName, String severity, String status, String title, Map<String, Object> evidence,
            String reviewDisposition, Instant firstObservedAt, Instant lastObservedAt, Instant resolvedAt
    ) {
    }

    public record PolicyResponse(
            String id, String version, String name, String severity, List<String> artifactTypes,
            List<String> requiredResourceFamilies, String description, String remediation,
            Map<String, String> controlMappings, boolean available, boolean enabled,
            long openFindings, long lifetimeFindings, Instant lastEvaluatedAt, double decisionCoverage,
            double decisionCoverageThreshold, String decisionCoverageStatus,
            long evaluatedArtifacts, long noDecisionCount
    ) {
    }

    public record PolicyScopeConditionResponse(String field, String operator, String value) {
    }

    public record PolicyScopeResponse(
            String mode, String conditionLogic, List<PolicyScopeConditionResponse> conditions,
            String updatedBy, Instant updatedAt
    ) {
    }

    public record PolicyExceptionResponse(
            UUID artifactId, String artifactName, String override, String reason, String createdBy, Instant createdAt
    ) {
    }

    public record PolicyParameterValueResponse(
            String key, String label, String type, List<String> options, String defaultValue, String helpText,
            String value
    ) {
    }

    public record PolicyConfigurationResponse(
            PolicyScopeResponse scope, List<PolicyExceptionResponse> exceptions,
            List<PolicyParameterValueResponse> parameters, long matchedArtifactCount, long totalArtifactCount
    ) {
    }

    public record PolicyAssistExplanationResponse(String summary, Instant generatedAt) {
    }

    public record PolicyAssistScopeSuggestionResponse(
            PolicyScopeConditionResponse suggestedCondition, String rationale, int falsePositiveCount
    ) {
    }

    record CoverageGate(
            double coverage,
            double threshold,
            String status,
            long evaluatedArtifacts,
            long noDecisionCount
    ) {
    }

    public record RunResponse(
            UUID id, String status, int recordsFetched, int recordsFailed,
            Instant startedAt, Instant completedAt, String errorMessage
    ) {
    }

    public record ScopeResponse(
            UUID id, UUID runId, String accountId, String region, String resourceFamily,
            String scopeKey, String status, int acceptedChunks, int expectedChunks,
            String diagnosticCode, Map<String, Object> diagnostics, Instant startedAt, Instant completedAt
    ) {
    }
}
