package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.aisecurity.azure.AiSecurityAzureKillSwitchService;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.EvaluationOutcome;
import com.prototype.vulnwatch.aisecurity.policy.AiSecurityPolicyRegistry;
import com.prototype.vulnwatch.aisecurity.policy.AiSecurityPolicyRegistry.PolicyDefinition;
import com.prototype.vulnwatch.aisecurity.policy.AiSecurityResourceFamilyCatalogue;
import com.prototype.vulnwatch.domain.Tenant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class AiSecurityPolicyEvaluationService {

    private static final List<String> GUARDRAIL_STRENGTHS = List.of("NONE", "LOW", "MEDIUM", "HIGH");

    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectMapper objectMapper;
    private final AiSecurityPolicyRegistry registry;
    private final AiSecurityResourceFamilyCatalogue resourceFamilies;
    private final AiSecurityAzureKillSwitchService azureKillSwitches;
    private boolean legacyFindingsEnabled;

    public AiSecurityPolicyEvaluationService(
            NamedParameterJdbcTemplate jdbc,
            ObjectMapper objectMapper,
            AiSecurityPolicyRegistry registry,
            AiSecurityResourceFamilyCatalogue resourceFamilies,
            AiSecurityAzureKillSwitchService azureKillSwitches
    ) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
        this.registry = registry;
        this.resourceFamilies = resourceFamilies;
        this.azureKillSwitches = azureKillSwitches;
    }

    @org.springframework.beans.factory.annotation.Value("${app.ai-security.grid.legacy-findings-enabled:false}")
    public void setLegacyFindingsEnabled(boolean legacyFindingsEnabled) {
        this.legacyFindingsEnabled = legacyFindingsEnabled;
    }

    void evaluateRunCurrentTenant(Tenant tenant, UUID runId) {
        Map<String, Boolean> enabled = effectivePolicyStates();
        List<ArtifactFact> artifacts = jdbc.query("""
                select id, artifact_type, native_kind, account_id, region, attributes_json::text
                  from ai_security_artifacts
                 where active = true
                """, (rs, rowNum) -> new ArtifactFact(
                rs.getObject("id", UUID.class),
                rs.getString("artifact_type"),
                rs.getString("native_kind"),
                rs.getString("account_id"),
                rs.getString("region"),
                readMap(rs.getString("attributes_json"))));

        for (PolicyDefinition policy : registry.all()) {
            if (!enabled.getOrDefault(policy.id(), false)
                    || (policy.id().startsWith("AZURE_") && azureKillSwitches.isPolicyDisabled(policy.id()))) {
                suppressPolicyFindings(policy.id());
                continue;
            }
            for (ArtifactFact artifact : artifacts) {
                if (!policy.artifactTypes().contains(artifact.artifactType())) {
                    continue;
                }
                if (!isApplicable(policy.id(), artifact.attributes())) {
                    continue;
                }
                Evaluation evaluation = hasCompleteEvidence(
                        runId, artifact.accountId(), artifact.region(), policy, artifact.nativeKind())
                        ? evaluate(policy.id(), artifact.attributes())
                        : new Evaluation(EvaluationOutcome.NO_DECISION, List.of("required snapshot scope incomplete"), Map.of());
                persistEvaluation(tenant, runId, policy, artifact, evaluation);
                if (legacyFindingsEnabled) {
                    reconcileFinding(tenant, policy, artifact, evaluation);
                }
            }
        }
    }

    private Map<String, Boolean> effectivePolicyStates() {
        return jdbc.query("""
                select d.policy_id,
                       case
                         when not d.available then false
                         else coalesce(s.enabled, d.default_enabled)
                       end as enabled
                  from platform.ai_security_policy_distribution d
                  left join ai_security_policy_settings s on s.policy_id = d.policy_id
                """, rs -> {
            java.util.LinkedHashMap<String, Boolean> values = new java.util.LinkedHashMap<>();
            while (rs.next()) {
                values.put(rs.getString("policy_id"), rs.getBoolean("enabled"));
            }
            return values;
        });
    }

    boolean hasCompleteEvidence(
            UUID runId, String accountId, String artifactRegion, PolicyDefinition policy) {
        return hasCompleteEvidence(runId, accountId, artifactRegion, policy, null);
    }

    boolean hasCompleteEvidence(
            UUID runId,
            String accountId,
            String artifactRegion,
            PolicyDefinition policy,
            String nativeKind
    ) {
        for (String family : requiredFamilies(policy, nativeKind)) {
            var requiredRegion = resourceFamilies.requiredRegion(family, artifactRegion);
            if (requiredRegion.isEmpty()) {
                return false;
            }
            Integer count = jdbc.queryForObject("""
                    select count(*)
                      from ai_security_snapshot_scopes
                     where run_id = :runId
                       and resource_family = :family
                       and account_id = :accountId
                       and region = :region
                       and status = 'COMPLETE'
                    """, new MapSqlParameterSource()
                    .addValue("runId", runId)
                    .addValue("family", family)
                    .addValue("accountId", accountId)
                    .addValue("region", requiredRegion.get()), Integer.class);
            if (count == null || count == 0) {
                return false;
            }
        }
        return true;
    }

    List<String> requiredFamilies(PolicyDefinition policy, String nativeKind) {
        String postureFamily = switch (nativeKind == null ? "" : nativeKind) {
            case "AZURE_AI_ACCOUNTS" -> "AZURE_AI_ACCOUNTS";
            case "AZURE_ML_WORKSPACES" -> "AZURE_ML_WORKSPACES";
            case "AZURE_SEARCH_SERVICES" -> "AZURE_SEARCH_SERVICES";
            default -> null;
        };
        if (postureFamily == null) {
            return policy.requiredResourceFamilies();
        }
        return switch (policy.id()) {
            case "AZURE_AI_UNRESTRICTED_PUBLIC_ACCESS" -> List.of(postureFamily);
            case "AZURE_AI_DIAGNOSTIC_LOGGING_DISABLED" ->
                    List.of(postureFamily, "AZURE_DIAGNOSTIC_SETTINGS");
            default -> policy.requiredResourceFamilies();
        };
    }

    Evaluation evaluate(String policyId, Map<String, Object> attributes) {
        return switch (policyId) {
            case "AWS_BEDROCK_PUBLIC_KB_S3" ->
                    booleanFact(attributes, "s3Public")
                            .map(value -> result(value, "S3 data source is public", attributes))
                            .orElseGet(() -> missing("s3Public"));
            case "AWS_BEDROCK_UNAUTH_LAMBDA_URL" -> {
                Object value = attributes.get("lambdaUrlAuthType");
                yield value == null
                        ? missing("lambdaUrlAuthType")
                        : result("NONE".equalsIgnoreCase(String.valueOf(value)),
                                "Action-group Lambda URL is unauthenticated", attributes);
            }
            case "AWS_BEDROCK_WILDCARD_AGENT_ROLE" ->
                    booleanFact(attributes, "iamWildcardActions")
                            .map(value -> result(value, "Execution role grants wildcard actions", attributes))
                            .orElseGet(() -> missing("iamWildcardActions"));
            case "AWS_BEDROCK_WEAK_GUARDRAIL" -> evaluateGuardrail(attributes);
            case "AWS_BEDROCK_INVOCATION_LOGGING_DISABLED" ->
                    booleanFact(attributes, "invocationLoggingEnabled")
                            .map(value -> result(!value, "Bedrock invocation logging is disabled", attributes))
                            .orElseGet(() -> missing("invocationLoggingEnabled"));
            case "AZURE_RAI_POLICY_NON_BLOCKING_FILTER" ->
                    booleanFact(attributes, "raiFilterEvidenceComplete")
                            .filter(Boolean::booleanValue)
                            .flatMap(ignored -> booleanFact(attributes, "raiNonBlockingFilterObserved"))
                            .map(value -> result(value,
                                    "Azure RAI policy contains an explicitly disabled or non-blocking filter",
                                    attributes))
                            .orElseGet(() -> missing("complete RAI content-filter configuration"));
            case "AZURE_AI_UNRESTRICTED_PUBLIC_ACCESS" ->
                    booleanFact(attributes, "publicNetworkUnrestricted")
                            .map(value -> result(value, "Azure AI public network access is unrestricted", attributes))
                            .orElseGet(() -> missing("publicNetworkUnrestricted"));
            case "AZURE_AI_LOCAL_AUTH_ENABLED" ->
                    booleanFact(attributes, "localAuthEnabled")
                            .map(value -> result(value, "Azure AI local authentication is enabled", attributes))
                            .orElseGet(() -> missing("localAuthEnabled"));
            case "AZURE_AI_DIAGNOSTIC_LOGGING_DISABLED" ->
                    booleanFact(attributes, "diagnosticLoggingEnabled")
                            .map(value -> result(!value, "Azure AI diagnostic logging is disabled", attributes))
                            .orElseGet(() -> missing("diagnosticLoggingEnabled"));
            case "AZURE_FOUNDRY_AGENT_CODE_INTERPRETER_ENABLED" ->
                    booleanFact(attributes, "codeInterpreterEnabled")
                            .map(value -> result(value, "Foundry agent Code Interpreter is enabled", attributes))
                            .orElseGet(() -> missing("codeInterpreterEnabled"));
            case "AZURE_ML_ENDPOINT_LOCAL_AUTH_ENABLED" ->
                    booleanFact(attributes, "mlLocalAuthEnabled")
                            .map(value -> result(value, "Azure ML endpoint local authentication is enabled", attributes))
                            .orElseGet(() -> missing("mlLocalAuthEnabled"));
            case "AZURE_SEARCH_LOCAL_ADMIN_AUTH_ENABLED" ->
                    booleanFact(attributes, "searchLocalAuthEnabled")
                            .map(value -> result(value, "Azure AI Search local admin authentication is enabled", attributes))
                            .orElseGet(() -> missing("searchLocalAuthEnabled"));
            case "AZURE_SEARCH_DATA_SOURCE_NON_IDENTITY_AUTH" ->
                    booleanFact(attributes, "authoritativeNonIdentityAuthentication")
                            .map(value -> result(value,
                                    "Azure AI Search data source does not use identity authentication", attributes))
                            .orElseGet(() -> missing("authoritativeNonIdentityAuthentication"));
            case "AZURE_BOT_PASSWORD_AUTH_WITHOUT_MANAGED_IDENTITY" ->
                    booleanFact(attributes, "botPasswordAuthWithoutManagedIdentity")
                            .map(value -> result(value,
                                    "Azure Bot uses password authentication without managed identity", attributes))
                            .orElseGet(() -> missing("botPasswordAuthWithoutManagedIdentity"));
            default -> new Evaluation(EvaluationOutcome.NOT_APPLICABLE, List.of(), Map.of());
        };
    }

    boolean isApplicable(String policyId, Map<String, Object> attributes) {
        String marker = switch (policyId) {
            case "AZURE_AI_UNRESTRICTED_PUBLIC_ACCESS" -> "publicNetworkUnrestricted";
            case "AZURE_AI_LOCAL_AUTH_ENABLED" -> "localAuthEnabled";
            case "AZURE_AI_DIAGNOSTIC_LOGGING_DISABLED" -> "diagnosticLoggingEnabled";
            case "AZURE_FOUNDRY_AGENT_CODE_INTERPRETER_ENABLED" -> "codeInterpreterEnabled";
            case "AZURE_ML_ENDPOINT_LOCAL_AUTH_ENABLED" -> "mlLocalAuthEnabled";
            case "AZURE_SEARCH_LOCAL_ADMIN_AUTH_ENABLED" -> "searchLocalAuthEnabled";
            case "AZURE_SEARCH_DATA_SOURCE_NON_IDENTITY_AUTH" -> "authoritativeNonIdentityAuthentication";
            case "AZURE_BOT_PASSWORD_AUTH_WITHOUT_MANAGED_IDENTITY" ->
                    "botPasswordAuthWithoutManagedIdentity";
            default -> null;
        };
        return marker == null || attributes.containsKey(marker);
    }

    private Evaluation evaluateGuardrail(Map<String, Object> attributes) {
        var attached = booleanFact(attributes, "guardrailAttached");
        if (attached.isEmpty()) {
            return missing("guardrailAttached");
        }
        if (!attached.get()) {
            return new Evaluation(EvaluationOutcome.NOT_APPLICABLE, List.of(), Map.of());
        }
        Object value = attributes.get("guardrailMinimumStrength");
        if (value == null) {
            return missing("guardrailMinimumStrength");
        }
        int strength = GUARDRAIL_STRENGTHS.indexOf(String.valueOf(value).toUpperCase());
        if (strength < 0) {
            return missing("recognized guardrailMinimumStrength");
        }
        return result(strength < GUARDRAIL_STRENGTHS.indexOf("MEDIUM"),
                "Attached guardrail is below MEDIUM strength", attributes);
    }

    private java.util.Optional<Boolean> booleanFact(Map<String, Object> attributes, String key) {
        Object value = attributes.get(key);
        if (value instanceof Boolean bool) {
            return java.util.Optional.of(bool);
        }
        if (value instanceof String string && ("true".equalsIgnoreCase(string) || "false".equalsIgnoreCase(string))) {
            return java.util.Optional.of(Boolean.parseBoolean(string));
        }
        return java.util.Optional.empty();
    }

    private Evaluation result(boolean fail, String reason, Map<String, Object> evidence) {
        return new Evaluation(fail ? EvaluationOutcome.FAIL : EvaluationOutcome.PASS, List.of(), Map.of(
                "reason", reason,
                "facts", evidence));
    }

    private Evaluation missing(String fact) {
        return new Evaluation(EvaluationOutcome.NO_DECISION, List.of(fact), Map.of());
    }

    private void persistEvaluation(
            Tenant tenant, UUID runId, PolicyDefinition policy, ArtifactFact artifact, Evaluation evaluation) {
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("id", UUID.randomUUID())
                .addValue("tenantId", tenant.getId())
                .addValue("runId", runId)
                .addValue("policyId", policy.id())
                .addValue("policyVersion", policy.version())
                .addValue("artifactId", artifact.id())
                .addValue("outcome", evaluation.outcome().name())
                .addValue("missing", json(evaluation.missingEvidence()))
                .addValue("evidence", json(evaluation.evidence()));
        jdbc.update("""
                insert into ai_security_policy_evaluations (
                    id, tenant_id, run_id, policy_id, policy_version, artifact_id,
                    outcome, missing_evidence_json, evidence_json
                ) values (
                    :id, :tenantId, :runId, :policyId, :policyVersion, :artifactId,
                    :outcome, cast(:missing as jsonb), cast(:evidence as jsonb)
                ) on conflict (tenant_id, run_id, policy_id, artifact_id) do update
                    set policy_version = excluded.policy_version,
                        outcome = excluded.outcome,
                        missing_evidence_json = excluded.missing_evidence_json,
                        evidence_json = excluded.evidence_json,
                        evaluated_at = now()
                """, params);
    }

    private void reconcileFinding(
            Tenant tenant, PolicyDefinition policy, ArtifactFact artifact, Evaluation evaluation) {
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("tenantId", tenant.getId())
                .addValue("policyId", policy.id())
                .addValue("artifactId", artifact.id());
        if (evaluation.outcome() == EvaluationOutcome.FAIL) {
            params.addValue("id", UUID.randomUUID())
                    .addValue("displayId", "AIF-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase())
                    .addValue("policyVersion", policy.version())
                    .addValue("severity", policy.severity())
                    .addValue("title", policy.name())
                    .addValue("evidence", json(evaluation.evidence()));
            jdbc.update("""
                    insert into ai_security_findings (
                        id, tenant_id, display_id, policy_id, policy_version, artifact_id,
                        severity, status, title, evidence_json, first_observed_at, last_observed_at
                    ) values (
                        :id, :tenantId, :displayId, :policyId, :policyVersion, :artifactId,
                        :severity, 'OPEN', :title, cast(:evidence as jsonb), now(), now()
                    ) on conflict (tenant_id, policy_id, artifact_id) do update
                        set policy_version = excluded.policy_version,
                            severity = excluded.severity,
                            status = 'OPEN',
                            title = excluded.title,
                            evidence_json = excluded.evidence_json,
                            last_observed_at = now(),
                            resolved_at = null
                    """, params);
        } else if (evaluation.outcome() == EvaluationOutcome.PASS) {
            jdbc.update("""
                    update ai_security_findings
                       set status = 'RESOLVED', resolved_at = now(), last_observed_at = now()
                     where tenant_id = :tenantId
                       and policy_id = :policyId
                       and artifact_id = :artifactId
                       and status = 'OPEN'
                    """, params);
        }
    }

    private void suppressPolicyFindings(String policyId) {
        jdbc.update("""
                update ai_security_findings
                   set status = 'SUPPRESSED_BY_POLICY', last_observed_at = now()
                 where policy_id = :policyId and status = 'OPEN'
                """, Map.of("policyId", policyId));
    }

    private Map<String, Object> readMap(String json) {
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
            throw new IllegalArgumentException("Unable to serialize AI Security policy evidence", ex);
        }
    }

    private record ArtifactFact(
            UUID id,
            String artifactType,
            String nativeKind,
            String accountId,
            String region,
            Map<String, Object> attributes
    ) {
    }

    record Evaluation(
            EvaluationOutcome outcome,
            List<String> missingEvidence,
            Map<String, Object> evidence
    ) {
    }
}
