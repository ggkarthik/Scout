package com.prototype.vulnwatch.aisecurity.service;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

/** Resolves all connector capability observations once per assessment run. */
@Service
public class AiGridCapabilityService {
    private static final List<String> DECISIVE = List.of("COMPLETE");
    private static final Set<String> AWS_GLOBAL_FAMILIES = Set.of("IAM_GLOBAL");
    private final NamedParameterJdbcTemplate jdbc;
    private final TenantSchemaExecutionService tenantExecution;

    public AiGridCapabilityService(NamedParameterJdbcTemplate jdbc, TenantSchemaExecutionService tenantExecution) {
        this.jdbc = jdbc;
        this.tenantExecution = tenantExecution;
    }

    public Map<CapabilityKey, CapabilityState> forRun(UUID runId) {
        Map<CapabilityKey, CapabilityState> result = new LinkedHashMap<>();
        jdbc.query("""
                select provider, capability_id, account_id, region, status, observed_at, expires_at
                  from ai_grid_capability_observations
                 where run_id = :runId
                 order by observed_at desc, id desc
                """, Map.of("runId", runId), rs -> {
            while (rs.next()) {
                CapabilityKey key = new CapabilityKey(rs.getString("provider"), rs.getString("capability_id"),
                        rs.getString("account_id"), rs.getString("region"));
                result.putIfAbsent(key, new CapabilityState(rs.getString("status"),
                        rs.getTimestamp("observed_at").toInstant(), timestamp(rs.getTimestamp("expires_at"))));
            }
            return null;
        });
        return Map.copyOf(result);
    }

    public List<String> gaps(Map<CapabilityKey, CapabilityState> index, String provider, String accountId,
                             String region, List<String> required) {
        List<String> gaps = new ArrayList<>();
        Instant now = Instant.now();
        for (String capability : required) {
            CapabilityState state = index.get(new CapabilityKey(provider, capability, accountId, region));
            if (state == null) state = index.get(new CapabilityKey(provider, capability, accountId, "GLOBAL"));
            if (state == null) { gaps.add("capability:" + capability + ":MISSING"); continue; }
            if (!DECISIVE.contains(state.status())) gaps.add("capability:" + capability + ":" + state.status());
            else if (state.expiresAt() == null || !state.expiresAt().isAfter(now)) gaps.add("capability:" + capability + ":STALE");
        }
        return List.copyOf(gaps);
    }

    /** Runtime capability evidence is authoritative only for the provider that produced the execution. */
    public List<String> runtimeGaps(Map<CapabilityKey, CapabilityState> index, String provider,
                                    List<String> required) {
        List<String> gaps = new ArrayList<>();
        Instant now = Instant.now();
        for (String capability : required) {
            boolean complete = index.entrySet().stream()
                    .filter(entry -> capability.equals(entry.getKey().capabilityId())
                            && provider.equals(entry.getKey().provider()))
                    .map(Map.Entry::getValue)
                    .anyMatch(state -> DECISIVE.contains(state.status()) && state.expiresAt() != null
                            && state.expiresAt().isAfter(now));
            if (!complete) gaps.add("capability:" + capability + ":MISSING_OR_STALE");
        }
        return List.copyOf(gaps);
    }

    /** Builds tenant-visible setup guidance from the governed capability catalog. */
    public String remediation(List<String> capabilityIds) {
        if (capabilityIds == null || capabilityIds.isEmpty()) return "Restore the required connector capability and run discovery.";
        List<String> values = jdbc.query("""
                select capability_id, remediation from platform.ai_grid_capability_definitions
                 where capability_id in (:capabilities) and lifecycle = 'ACTIVE'
                 order by capability_id
                """, Map.of("capabilities", capabilityIds), (rs, n) ->
                rs.getString("capability_id") + ": " + rs.getString("remediation"));
        return values.isEmpty() ? "Restore the required connector capability and run discovery."
                : String.join(" ", values);
    }

    /**
     * Returns only the calling tenant's newest connector observations. Capability observations
     * are tenant-schema data, so this boundary must establish the tenant context before querying.
     */
    public List<CapabilityView> latest(Tenant tenant) {
        return tenantExecution.run(tenant, this::latestInTenantContext);
    }

    private List<CapabilityView> latestInTenantContext() {
        return jdbc.query("""
                select distinct on (o.provider,o.capability_id,o.account_id,o.region)
                       o.provider,o.capability_id,o.connector,o.account_id,o.region,o.resource_family,
                       o.status,o.observed_at,o.expires_at,o.reason_code,o.evidence_scopes_json::text,
                       o.detail,d.optional,d.remediation
                  from ai_grid_capability_observations o
                  join platform.ai_grid_capability_definitions d on d.capability_id=o.capability_id
                 order by o.provider,o.capability_id,o.account_id,o.region,o.observed_at desc,o.id desc
                """, (rs, n) -> new CapabilityView(rs.getString(1), rs.getString(2), rs.getString(3),
                rs.getString(4), rs.getString(5), rs.getString(6), rs.getString(7), rs.getTimestamp(8).toInstant(),
                timestamp(rs.getTimestamp(9)), rs.getString(10), rs.getString(11), rs.getString(12),
                rs.getBoolean(13), rs.getString(14)));
    }

    public void registerRun(Tenant tenant, UUID runId, String provider, UUID connectorId, String accountId,
                            List<String> regions, List<String> enabledFamilies) {
        reconcileAbandonedRuns(tenant);
        tenantExecution.run(tenant, () -> {
            Map<String, List<String>> familiesByCapability = new LinkedHashMap<>();
            for (String family : enabledFamilies) {
                for (String capability : declaredCapabilities(provider, family)) {
                    familiesByCapability.computeIfAbsent(capability, ignored -> new ArrayList<>()).add(family);
                }
            }
            if (familiesByCapability.isEmpty()) return null;
            Integer known = jdbc.queryForObject("""
                    select count(*) from platform.ai_grid_capability_definitions
                     where capability_id in (:ids) and lifecycle='ACTIVE'
                    """, Map.of("ids", familiesByCapability.keySet()), Integer.class);
            if (known == null || known != familiesByCapability.size()) {
                throw new IllegalStateException("Collector declares an unknown or inactive capability");
            }
            List<String> effectiveRegions = regions == null || regions.isEmpty() ? List.of("GLOBAL") : regions;
            for (Map.Entry<String, List<String>> entry : familiesByCapability.entrySet()) {
                boolean global = "AWS".equalsIgnoreCase(provider)
                        && entry.getValue().stream().allMatch(AWS_GLOBAL_FAMILIES::contains);
                for (String region : global ? List.of("GLOBAL") : effectiveRegions) {
                    List<String> scopeKeys = entry.getValue().stream().map(family -> scopeKey(
                            provider, accountId,
                            "AWS".equalsIgnoreCase(provider) && AWS_GLOBAL_FAMILIES.contains(family)
                                    ? "GLOBAL" : region,
                            family)).distinct().sorted().toList();
                    jdbc.update("""
                            insert into ai_grid_capability_manifests
                                (id,tenant_id,run_id,provider,connector_id,account_id,region,capability_id,
                                 required_scope_keys_json,status)
                            values (:id,:tenantId,:runId,:provider,:connectorId,:accountId,:region,:capability,
                                    cast(:scopeKeys as jsonb),'REGISTERED')
                            on conflict (tenant_id,run_id,provider,account_id,region,capability_id) do nothing
                            """, new MapSqlParameterSource().addValue("id", UUID.randomUUID())
                            .addValue("tenantId", tenant.getId()).addValue("runId", runId)
                            .addValue("provider", provider.toUpperCase()).addValue("connectorId", connectorId)
                            .addValue("accountId", accountId).addValue("region", region)
                            .addValue("capability", entry.getKey()).addValue("scopeKeys", jsonArray(scopeKeys)));
                }
            }
            return null;
        });
    }

    /** Finalizes orphaned manifests after a process restart so stale COMPLETE evidence cannot survive silently. */
    public int reconcileAbandonedRuns(Tenant tenant) {
        List<UUID> abandoned = tenantExecution.run(tenant, () -> jdbc.query("""
                select distinct run_id from ai_grid_capability_manifests
                 where status='REGISTERED' and created_at < now() - interval '1 hour'
                 order by run_id
                """, (rs, row) -> rs.getObject(1, UUID.class)));
        abandoned.forEach(runId -> finalizeRun(tenant, runId));
        return abandoned.size();
    }

    public void finalizeRun(Tenant tenant, UUID runId) {
        tenantExecution.run(tenant, () -> {
            List<CapabilityManifest> manifests = jdbc.query("""
                    select id,provider,connector_id,account_id,region,capability_id
                      from ai_grid_capability_manifests
                     where run_id=:runId and status='REGISTERED'
                     order by provider,account_id,region,capability_id
                    """, Map.of("runId", runId), (rs, row) -> new CapabilityManifest(
                    rs.getObject(1, UUID.class), rs.getString(2), rs.getObject(3, UUID.class),
                    rs.getString(4), rs.getString(5), rs.getString(6)));
            for (CapabilityManifest manifest : manifests) {
                List<ScopeEvidence> evidence = jdbc.query("""
                        select expected.scope_key,scope.resource_family,scope.status
                          from ai_grid_capability_manifests manifest
                          cross join lateral jsonb_array_elements_text(manifest.required_scope_keys_json)
                               expected(scope_key)
                          left join ai_security_snapshot_scopes scope
                            on scope.run_id=manifest.run_id and scope.scope_key=expected.scope_key
                         where manifest.id=:id order by expected.scope_key
                        """, Map.of("id", manifest.id()), (rs, row) -> new ScopeEvidence(
                        rs.getString(2), rs.getString(3), rs.getString(1)));
                List<String> missing = evidence.stream().filter(item -> item.status() == null)
                        .map(ScopeEvidence::scopeKey).toList();
                String status = missing.isEmpty()
                        ? aggregateStatus(evidence.stream().map(ScopeEvidence::status).toList()) : "PARTIAL";
                String reason = missing.isEmpty() ? reasonCode(status) : "MISSING_EVIDENCE_SCOPE";
                String detail = missing.isEmpty() ? "Finalized from all registered evidence scopes"
                        : "missing required collector scopes: " + String.join(",", missing);
                jdbc.update("""
                        insert into ai_grid_capability_observations
                            (id,tenant_id,run_id,provider,capability_id,connector,account_id,region,resource_family,
                             observed_at,expires_at,status,reason_code,evidence_scopes_json,detail)
                        values (:id,:tenantId,:runId,:provider,:capability,:connector,:accountId,:region,'RUN_MANIFEST',
                                :observedAt,:expiresAt,:status,:reasonCode,cast(:evidenceScopes as jsonb),:detail)
                        on conflict (tenant_id,run_id,provider,capability_id,account_id,region) do update set
                            observed_at=excluded.observed_at,expires_at=excluded.expires_at,status=excluded.status,
                            reason_code=excluded.reason_code,evidence_scopes_json=excluded.evidence_scopes_json,
                            detail=excluded.detail,resource_family=excluded.resource_family
                        """, new MapSqlParameterSource().addValue("id", UUID.randomUUID())
                        .addValue("tenantId", tenant.getId()).addValue("runId", runId)
                        .addValue("provider", manifest.provider()).addValue("capability", manifest.capabilityId())
                        .addValue("connector", manifest.connectorId().toString()).addValue("accountId", manifest.accountId())
                        .addValue("region", manifest.region()).addValue("observedAt", Timestamp.from(Instant.now()))
                        .addValue("expiresAt", Timestamp.from(Instant.now().plusSeconds(86400)))
                        .addValue("status", status).addValue("reasonCode", reason)
                        .addValue("evidenceScopes", jsonArray(evidence.stream().filter(item -> item.status() != null)
                                .map(ScopeEvidence::scopeKey).toList())).addValue("detail", detail));
                jdbc.update("update ai_grid_capability_manifests set status='FINALIZED',finalized_at=now() where id=:id",
                        Map.of("id", manifest.id()));
            }
            return null;
        });
    }

    private String scopeKey(String provider, String accountId, String region, String family) {
        return provider.toUpperCase() + ":" + accountId + ":" + region + ":" + family;
    }

    private String aggregateStatus(List<String> statuses) {
        for (String status : List.of("UNAUTHORIZED", "ERROR", "UNSUPPORTED_API", "DISABLED", "PARTIAL"))
            if (statuses.contains(status)) return status;
        return statuses.stream().allMatch("COMPLETE"::equals) ? "COMPLETE" : "PARTIAL";
    }

    public Map<CapabilityKey, CapabilityState> latestIndex() {
        Map<CapabilityKey, CapabilityState> result = new LinkedHashMap<>();
        jdbc.query("""
                select distinct on (provider,capability_id,account_id,region)
                       provider,capability_id,account_id,region,status,observed_at,expires_at
                  from ai_grid_capability_observations
                 order by provider,capability_id,account_id,region,observed_at desc,id desc
                """, rs -> {
            while (rs.next()) result.put(new CapabilityKey(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4)),
                    new CapabilityState(rs.getString(5), rs.getTimestamp(6).toInstant(), timestamp(rs.getTimestamp(7))));
            return null;
        });
        return Map.copyOf(result);
    }

    /** Records an asynchronous runtime-source capability without coupling it to an inventory run. */
    public void recordRuntimeCapabilities(Tenant tenant, String provider, String connector, String accountId,
                                          String region, String status, String detail,
                                          List<String> capabilityIds) {
        if (capabilityIds == null || capabilityIds.isEmpty()) return;
        tenantExecution.run(tenant, () -> {
            UUID observationRun = UUID.randomUUID();
            Instant observedAt = Instant.now();
            for (String capabilityId : capabilityIds) {
                jdbc.update("""
                        insert into ai_grid_capability_observations
                            (id,tenant_id,run_id,provider,capability_id,connector,account_id,region,
                             resource_family,connector_version,observed_at,expires_at,status,reason_code,
                             evidence_scopes_json,detail)
                        select :id,:tenantId,:runId,:provider,d.capability_id,:connector,:accountId,:region,
                               d.resource_family,'v1',:observedAt,:expiresAt,:status,:reason,
                               cast(:scopes as jsonb),:detail
                          from platform.ai_grid_capability_definitions d
                         where d.capability_id=:capability and d.lifecycle='ACTIVE'
                        """, new MapSqlParameterSource().addValue("id", UUID.randomUUID())
                        .addValue("tenantId", tenant.getId()).addValue("runId", observationRun)
                        .addValue("provider", provider).addValue("capability", capabilityId)
                        .addValue("connector", connector).addValue("accountId", accountId)
                        .addValue("region", region == null ? "GLOBAL" : region)
                        .addValue("observedAt", Timestamp.from(observedAt))
                        .addValue("expiresAt", Timestamp.from(observedAt.plusSeconds(86400)))
                        .addValue("status", status).addValue("reason", reasonCode(status))
                        .addValue("scopes", "[\"" + capabilityId + "\"]").addValue("detail", detail));
            }
            return null;
        });
    }

    public static List<String> declaredCapabilities(String provider, String resourceFamily) {
        String family = resourceFamily == null ? "" : resourceFamily.toUpperCase();
        if ("AWS".equalsIgnoreCase(provider)) {
            return switch (family) {
                case "EFFECTIVE_ACCESS", "AWS_EFFECTIVE_ACCESS" -> List.of("AWS_EFFECTIVE_ACCESS");
                case "LINKED_DATA_STORES", "AWS_LINKED_DATA_STORES" -> List.of("AWS_LINKED_DATA_STORES");
                case "CONSUMPTION_TELEMETRY", "AWS_CONSUMPTION_TELEMETRY" -> List.of("AWS_CONSUMPTION_TELEMETRY");
                case "MODEL_DATA_PROVENANCE", "AWS_MODEL_DATA_PROVENANCE" -> List.of("AWS_MODEL_DATA_PROVENANCE");
                case "BEDROCK_AGENT_VERSIONS" -> List.of("BEDROCK_AGENT_VERSIONS_ALIASES");
                case "BEDROCK_AGENTS" -> List.of("BEDROCK_AGENTS");
                case "BEDROCK_GUARDRAILS" -> List.of("BEDROCK_GUARDRAILS");
                case "BEDROCK_KNOWLEDGE_BASES", "BEDROCK_DATA_SOURCES", "BEDROCK_DATA_STORES" -> List.of("BEDROCK_KNOWLEDGE_BASES");
                case "BEDROCK_DEPLOYABLE_MODELS", "BEDROCK_INFERENCE_PROFILES", "BEDROCK_MODEL_CUSTOMIZATION_JOBS" -> List.of("BEDROCK_MODELS_JOBS");
                case "BEDROCK_PROMPTS", "BEDROCK_FLOWS", "BEDROCK_AGENT_DEFINITIONS" -> List.of("BEDROCK_PROMPTS_TOOLS");
                case "BEDROCK_INVOCATION_LOGGING" -> List.of("BEDROCK_INVOCATION_LOGGING");
                case "IAM_GLOBAL" -> List.of("IAM_ROLE_POLICIES", "AWS_EFFECTIVE_ACCESS");
                case "LAMBDA_URLS" -> List.of("LAMBDA_URLS");
                case "S3_EXPOSURE" -> List.of("AWS_LINKED_DATA_STORES");
                case "AWS_AGENTCORE_RUNTIME", "AWS_AGENTCORE_RUNTIMES", "AWS_AGENTCORE_BROWSERS",
                        "AWS_AGENTCORE_CODE_INTERPRETERS", "AWS_AGENTCORE_MEMORIES" -> List.of("AGENTCORE_RUNTIME_TOOLS");
                case "AWS_AGENTCORE_GATEWAYS", "AWS_AGENTCORE_GATEWAY_TARGETS" -> List.of("AGENTCORE_GATEWAYS_TARGETS");
                case "SAGEMAKER_DOMAINS", "SAGEMAKER_MODEL_REGISTRY", "SAGEMAKER_ENDPOINTS",
                        "SAGEMAKER_ENDPOINT_CONFIGURATIONS", "SAGEMAKER_JOBS", "SAGEMAKER_PIPELINES",
                        "SAGEMAKER_COMPUTE", "SAGEMAKER_EXECUTION_ROLES", "SAGEMAKER_NETWORKING",
                        "SAGEMAKER_SPACES" -> List.of("SAGEMAKER_DOMAINS_MODELS_ENDPOINTS");
                case "AWS_MACIE_PII" -> List.of("MACIE_CLASSIFICATION");
                default -> List.of();
            };
        }
        if ("AZURE".equalsIgnoreCase(provider)) {
            if (family.contains("EFFECTIVE_ACCESS")) return List.of("AZURE_EFFECTIVE_ACCESS");
            if (family.contains("LINKED_DATA_STORES")) return List.of("AZURE_LINKED_DATA_STORES");
            if (family.contains("SEARCH_MCP_SECURITY")) return List.of("AZURE_SEARCH_MCP_SECURITY");
            if (family.contains("CONSUMPTION_TELEMETRY")) return List.of("AZURE_CONSUMPTION_TELEMETRY");
            if (family.contains("MODEL_DATA_PROVENANCE")) return List.of("AZURE_MODEL_DATA_PROVENANCE");
            if (family.startsWith("AZURE_AI_ACCOUNTS")) return List.of("AI_ACCOUNTS");
            if (family.startsWith("AZURE_DIAGNOSTIC")) return List.of("DIAGNOSTIC_SETTINGS");
            if (family.startsWith("AZURE_RAI") || family.startsWith("AZURE_FOUNDRY_DEPLOYMENTS")) return List.of("FOUNDRY_DEPLOYMENTS_RAI");
            if (family.startsWith("AZURE_FOUNDRY_AGENTS") || family.startsWith("AZURE_FOUNDRY_AGENT_TOOLS")) return List.of("FOUNDRY_AGENTS_TOOLS");
            if (family.startsWith("AZURE_ML_")) return List.of("ML_WORKSPACES_ENDPOINTS");
            if (family.startsWith("AZURE_SEARCH")) return List.of("SEARCH_CONTROL_PLANE");
            if (family.startsWith("AZURE_BOT")) return List.of("BOT_CONFIGURATION");
            if (family.startsWith("AZURE_RBAC")) return List.of("RBAC_ASSIGNMENTS");
            if (family.startsWith("AZURE_PURVIEW")) return List.of("PURVIEW_CLASSIFICATION");
        }
        if ("MICROSOFT_COPILOT".equalsIgnoreCase(provider) && "COPILOT_STUDIO".equals(family)) {
            return List.of("COPILOT_STUDIO_METADATA");
        }
        return List.of();
    }

    private String reasonCode(String status) {
        return switch (status) {
            case "COMPLETE" -> "OBSERVED";
            case "DISABLED" -> "CONNECTOR_DISABLED";
            case "UNAUTHORIZED" -> "MISSING_PERMISSION";
            case "UNSUPPORTED_API" -> "UNSUPPORTED_API";
            case "ERROR" -> "COLLECTOR_ERROR";
            default -> "PARTIAL_EVIDENCE";
        };
    }

    private String jsonArray(List<String> values) {
        return values.stream().map(value -> "\"" + escapeJson(value) + "\"")
                .collect(java.util.stream.Collectors.joining(",", "[", "]"));
    }

    private String escapeJson(String value) {
        return value == null ? "" : value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private Instant timestamp(Timestamp value) { return value == null ? null : value.toInstant(); }
    public record CapabilityKey(String provider, String capabilityId, String accountId, String region) {}
    public record CapabilityState(String status, Instant observedAt, Instant expiresAt) {}
    public record CapabilityView(String provider, String capabilityId, String connector, String accountId, String region,
                                 String resourceFamily, String status, Instant observedAt, Instant expiresAt,
                                 String reasonCode, String evidenceScopesJson, String detail,
                                 boolean optional, String remediation) {}
    private record ScopeEvidence(String family, String status, String scopeKey) {}
    private record CapabilityManifest(UUID id, String provider, UUID connectorId, String accountId,
                                      String region, String capabilityId) {}
}
