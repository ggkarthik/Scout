package com.prototype.vulnwatch.aisecurity.service;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ObservationEnvelopeV1;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ScopeStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

/** Resolves all connector capability observations once per assessment run. */
@Service
public class AiGridCapabilityService {
    private static final List<String> DECISIVE = List.of("COMPLETE");
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
                       o.status,o.observed_at,o.expires_at,o.detail,d.optional,d.remediation
                  from ai_grid_capability_observations o
                  join platform.ai_grid_capability_definitions d on d.capability_id=o.capability_id
                 order by o.provider,o.capability_id,o.account_id,o.region,o.observed_at desc,o.id desc
                """, (rs, n) -> new CapabilityView(rs.getString(1), rs.getString(2), rs.getString(3),
                rs.getString(4), rs.getString(5), rs.getString(6), rs.getString(7), rs.getTimestamp(8).toInstant(),
                timestamp(rs.getTimestamp(9)), rs.getString(10), rs.getBoolean(11), rs.getString(12)));
    }

    /** Persist one observation per capability represented by a completed collector scope. */
    public void recordScope(Tenant tenant, ObservationEnvelopeV1 envelope, ScopeStatus scopeStatus) {
        for (String capability : capabilitiesFor(envelope.provider(), envelope.resourceFamily())) {
            jdbc.update("""
                    insert into ai_grid_capability_observations
                        (id,tenant_id,run_id,provider,capability_id,connector,account_id,region,resource_family,
                         observed_at,expires_at,status,detail)
                    values (:id,:tenantId,:runId,:provider,:capability,:connector,:accountId,:region,:family,
                            :observedAt,:expiresAt,:status,:detail)
                    on conflict (tenant_id,run_id,provider,capability_id,account_id,region) do update set
                        observed_at=excluded.observed_at,expires_at=excluded.expires_at,status=excluded.status,
                        detail=excluded.detail,resource_family=excluded.resource_family
                    """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                    .addValue("runId", envelope.runId()).addValue("provider", envelope.provider().toUpperCase())
                    .addValue("capability", capability).addValue("connector", envelope.connectorId().toString())
                    .addValue("accountId", envelope.accountId()).addValue("region", envelope.region())
                    .addValue("family", envelope.resourceFamily()).addValue("observedAt", Timestamp.from(envelope.observedAt()))
                    .addValue("expiresAt", Timestamp.from(envelope.observedAt().plusSeconds(86400)))
                    .addValue("status", capabilityStatus(scopeStatus)).addValue("detail", "collector scope " + envelope.scopeKey()));
        }
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

    private List<String> capabilitiesFor(String provider, String resourceFamily) {
        String family = resourceFamily == null ? "" : resourceFamily.toUpperCase();
        if ("AWS".equalsIgnoreCase(provider)) {
            if (family.contains("EFFECTIVE_ACCESS")) return List.of("AWS_EFFECTIVE_ACCESS");
            if (family.contains("LINKED_DATA_STORES")) return List.of("AWS_LINKED_DATA_STORES");
            if (family.contains("CONSUMPTION_TELEMETRY")) return List.of("AWS_CONSUMPTION_TELEMETRY");
            if (family.contains("MODEL_DATA_PROVENANCE")) return List.of("AWS_MODEL_DATA_PROVENANCE");
            if (family.startsWith("BEDROCK_AGENTS")) return List.of("BEDROCK_AGENTS");
            if (family.startsWith("BEDROCK_GUARDRAILS")) return List.of("BEDROCK_GUARDRAILS");
            if (family.startsWith("BEDROCK_KNOWLEDGE") || family.startsWith("BEDROCK_DATA_")) return List.of("BEDROCK_KNOWLEDGE_BASES");
            if (family.startsWith("BEDROCK_DEPLOYABLE") || family.startsWith("BEDROCK_INFERENCE") || family.startsWith("BEDROCK_MODEL_")) return List.of("BEDROCK_MODELS_JOBS");
            if (family.startsWith("BEDROCK_INVOCATION")) return List.of("BEDROCK_INVOCATION_LOGGING");
            if (family.startsWith("IAM")) return List.of("IAM_ROLE_POLICIES");
            if (family.startsWith("LAMBDA")) return List.of("LAMBDA_URLS");
            if (family.startsWith("AWS_AGENTCORE")) return List.of("AGENTCORE_GATEWAYS_TARGETS");
            if (family.startsWith("SAGEMAKER")) return List.of("SAGEMAKER_DOMAINS_MODELS_ENDPOINTS");
            if (family.startsWith("AWS_MACIE")) return List.of("MACIE_CLASSIFICATION");
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
        return List.of();
    }

    private String capabilityStatus(ScopeStatus status) {
        return switch (status) {
            case COMPLETE -> "COMPLETE";
            case DISABLED -> "DISABLED";
            case UNAUTHORIZED -> "UNAUTHORIZED";
            case PARTIAL -> "PARTIAL";
            case FAILED -> "ERROR";
            case UNSUPPORTED -> "UNSUPPORTED_API";
        };
    }

    private Instant timestamp(Timestamp value) { return value == null ? null : value.toInstant(); }
    public record CapabilityKey(String provider, String capabilityId, String accountId, String region) {}
    public record CapabilityState(String status, Instant observedAt, Instant expiresAt) {}
    public record CapabilityView(String provider, String capabilityId, String connector, String accountId, String region,
                                 String resourceFamily, String status, Instant observedAt, Instant expiresAt,
                                 String detail, boolean optional, String remediation) {}
}
