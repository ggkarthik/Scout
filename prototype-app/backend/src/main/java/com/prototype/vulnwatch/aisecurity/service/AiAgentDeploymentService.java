package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

/** Informational deployment metadata. Never read by assessment, grouping or runtime resolution. */
@Service
public class AiAgentDeploymentService {
    public enum Status { SERVED, NOT_CURRENTLY_SERVED, UNVERIFIED }
    public enum Reason {
        VERIFIED_SERVING_ROUTE, NO_ALIAS_ROUTE, NO_SERVING_ENDPOINT, NO_ACTIVE_DEPLOYMENT,
        ZERO_TRAFFIC_ALLOCATION, NOT_PUBLISHED, NO_ENABLED_CHANNEL, NO_SERVING_ROUTE,
        NO_EVIDENCE, STALE_EVIDENCE, INCOMPLETE_SCOPE, PERMISSION_DENIED, UNSUPPORTED_API,
        UNSUPPORTED_CHANNEL_EVIDENCE, COLLECTION_DISABLED, BUDGET_EXHAUSTED, PROVIDER_ERROR,
        UNRESOLVED_IDENTITY, UNRESOLVED_VERSION, AMBIGUOUS_ROUTE_STATE
    }
    public record Evidence(String family, UUID scopeId, UUID runId, Instant observedAt,
                           String collectionStatus, Reason reasonCode, List<UUID> routeIds) { }
    public record VerifiedObservation(Status status, Reason reasonCode, Instant observedAt, Instant expiresAt) { }
    public record Metadata(Status status, Reason reasonCode, Instant observedAt, Instant expiresAt,
                           List<Evidence> evidenceReferences, VerifiedObservation lastVerifiedObservation) {
        public Metadata {
            if (status == null || reasonCode == null || !validReason(status, reasonCode)) {
                throw new IllegalArgumentException("Deployment status and reason do not match the closed contract");
            }
            evidenceReferences = List.copyOf(evidenceReferences);
        }
    }
    static boolean validReason(Status status, Reason reason) {
        return switch (status) {
            case SERVED -> reason == Reason.VERIFIED_SERVING_ROUTE;
            case NOT_CURRENTLY_SERVED -> Set.of(Reason.NO_ALIAS_ROUTE, Reason.NO_SERVING_ENDPOINT,
                    Reason.NO_ACTIVE_DEPLOYMENT, Reason.ZERO_TRAFFIC_ALLOCATION, Reason.NOT_PUBLISHED,
                    Reason.NO_ENABLED_CHANNEL, Reason.NO_SERVING_ROUTE).contains(reason);
            case UNVERIFIED -> reason != Reason.VERIFIED_SERVING_ROUTE && !validReason(Status.NOT_CURRENTLY_SERVED, reason);
        };
    }
    public record Agent(UUID id, String nativeKind) { }
    public record Scope(UUID agentId, UUID id, UUID runId, String family, String status, String diagnostic,
                        Instant observedAt, boolean completePagination) { }
    public record Edge(UUID runId, UUID source, UUID target, String type) { }
    public record Resource(UUID runId, UUID id, String nativeKind, JsonNode attributes) { }
    static final String SCOPE_QUERY = """
                with applicable as (
                    select a.id agent_id, s.*,
                           row_number() over (partition by a.id order by s.completed_at desc, s.started_at desc, s.id) latest
                      from ai_security_artifacts a
                      join ai_security_snapshot_scopes s on s.provider = a.provider
                       and s.account_id = a.account_id and s.region = a.region
                       and s.resource_family = case a.native_kind
                           when 'AWS_BEDROCK_AGENT' then 'BEDROCK_AGENT_ROUTES'
                           when 'AWS_AGENTCORE_RUNTIME' then 'AWS_AGENTCORE_RUNTIMES'
                           when 'AZURE_FOUNDRY_AGENTS' then 'AZURE_FOUNDRY_AGENT_ROUTES'
                           when 'AZURE_CLASSIC_FOUNDRY_AGENTS' then 'AZURE_CLASSIC_FOUNDRY_AGENT_ROUTES'
                           when 'MICROSOFT_COPILOT' then 'COPILOT_STUDIO' end
                     where a.id in (:ids) and s.completed_at is not null
                )
                select * from applicable where latest = 1 or status = 'COMPLETE' order by agent_id, latest
                """;
    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectMapper mapper;
    public AiAgentDeploymentService(NamedParameterJdbcTemplate jdbc, ObjectMapper mapper) {
        this.jdbc = jdbc;
        this.mapper = mapper;
    }

    public Map<UUID, Metadata> resolve(List<Agent> agents, Instant now) {
        List<Agent> logical = agents.stream().filter(a -> AiAgentInventoryClassification.isAgent(a.nativeKind())).toList();
        if (logical.isEmpty()) return Map.of();
        Map<String, Object> params = Map.of("ids", logical.stream().map(Agent::id).toList());
        Integer hours = jdbc.queryForObject("select coalesce(max(freshness_hours), 24) from ai_agent_deployment_settings",
                Map.of(), Integer.class);
        Duration ttl = Duration.ofHours(hours == null ? 24 : hours);
        // Retained complete attempts allow the last verified observation to survive newer ambiguous evidence.
        List<Scope> scopes = jdbc.query(SCOPE_QUERY, params, (rs, n) -> new Scope(rs.getObject("agent_id", UUID.class), rs.getObject("id", UUID.class),
                rs.getObject("run_id", UUID.class), rs.getString("resource_family"), rs.getString("status"),
                rs.getString("diagnostic_code"), rs.getTimestamp("started_at").toInstant(),
                rs.getInt("accepted_chunks") == rs.getInt("expected_chunks")));
        Set<UUID> disabled = new java.util.HashSet<>(jdbc.queryForList("""
                select a.id from ai_security_artifacts a where a.id in (:ids) and (
                    (a.provider <> 'MICROSOFT_COPILOT' and exists (
                        select 1 from ai_security_connector_configs c where c.provider=a.provider and c.account_id=a.account_id)
                     and not exists (select 1 from ai_security_connector_configs c
                        where c.provider=a.provider and c.account_id=a.account_id and c.enabled))
                    or (a.provider='MICROSOFT_COPILOT' and exists (
                        select 1 from ai_security_copilot_studio_configs c where c.organization_url=a.account_id)
                     and not exists (select 1 from ai_security_copilot_studio_configs c
                        where c.organization_url=a.account_id and c.discovery_enabled and not c.kill_switch)))
                """, params, UUID.class));
        List<UUID> runs = scopes.stream().map(Scope::runId).distinct().toList();
        List<Edge> edges = List.of();
        List<Resource> resources = List.of();
        if (!runs.isEmpty()) {
            Map<String, Object> relatedParams = Map.of("ids", params.get("ids"), "runs", runs);
            edges = jdbc.query("""
                    select r.run_id, r.source_artifact_id, r.target_artifact_id, r.relationship_type
                      from ai_grid_relationship_snapshots r
                     where r.run_id in (:runs) and (
                         r.source_artifact_id in (:ids) or r.target_artifact_id in (:ids)
                         or r.source_artifact_id in (
                             select c.target_artifact_id from ai_grid_relationship_snapshots c
                              where c.run_id = r.run_id and c.source_artifact_id in (:ids)
                                and c.relationship_type in ('HAS_COMPONENT','HAS_DEPLOYMENT','HAS_ENDPOINT')))
                    """, relatedParams, (rs, n) -> new Edge(rs.getObject(1, UUID.class), rs.getObject(2, UUID.class),
                    rs.getObject(3, UUID.class), rs.getString(4)));
            Set<UUID> ids = new java.util.HashSet<>(logical.stream().map(Agent::id).toList());
            edges.forEach(e -> { ids.add(e.source()); ids.add(e.target()); });
            resources = jdbc.query("""
                    select m.run_id, m.artifact_id, b.content_json::text
                      from ai_grid_snapshot_manifests m join ai_grid_snapshot_bodies b on b.id = m.body_id
                     where m.run_id in (:runs) and m.artifact_id in (:ids)
                    """, Map.of("runs", runs, "ids", ids), (rs, n) -> {
                JsonNode body = parse(rs.getString(3));
                return new Resource(rs.getObject(1, UUID.class), rs.getObject(2, UUID.class),
                        body.path("nativeKind").asText(), body.path("attributes"));
            });
        }
        Map<UUID, Metadata> result = new LinkedHashMap<>();
        for (Agent agent : logical) {
            List<Scope> matching = scopes.stream().filter(s -> s.agentId().equals(agent.id())).toList();
            if (matching.isEmpty()) {
                Reason reason = disabled.contains(agent.id()) ? Reason.COLLECTION_DISABLED : agent.nativeKind().startsWith("AZURE_") ? Reason.UNSUPPORTED_API : Reason.NO_EVIDENCE;
                result.put(agent.id(), unverified(reason, null, ttl, List.of()));
                continue;
            }
            Metadata latest = disabled.contains(agent.id())
                    ? unverified(Reason.COLLECTION_DISABLED, matching.get(0), ttl, List.of())
                    : evaluate(agent, matching.get(0), edges, resources, now, ttl);
            VerifiedObservation historical = null;
            for (Scope scope : matching) {
                Metadata past = evaluate(agent, scope, edges, resources, scope.observedAt(), ttl);
                if (past.status() != Status.UNVERIFIED) {
                    historical = new VerifiedObservation(past.status(), past.reasonCode(), past.observedAt(), past.expiresAt());
                    break;
                }
            }
            result.put(agent.id(), new Metadata(latest.status(), latest.reasonCode(), latest.observedAt(), latest.expiresAt(),
                    latest.evidenceReferences(), historical));
        }
        return result;
    }

    /** Connector/family setup actions remain informational and do not enter policy coverage gaps. */
    public void reconcileScope(com.prototype.vulnwatch.domain.Tenant tenant,
                               com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ObservationEnvelopeV1 envelope) {
        if (!Set.of("BEDROCK_AGENT_ROUTES", "AWS_AGENTCORE_RUNTIMES", "AZURE_FOUNDRY_AGENT_ROUTES", "COPILOT_STUDIO")
                .contains(envelope.resourceFamily())) return;
        String kind = switch (envelope.resourceFamily()) {
            case "BEDROCK_AGENT_ROUTES" -> "AWS_BEDROCK_AGENT";
            case "AWS_AGENTCORE_RUNTIMES" -> "AWS_AGENTCORE_RUNTIME";
            case "COPILOT_STUDIO" -> "MICROSOFT_COPILOT";
            default -> "AZURE_FOUNDRY_AGENTS";
        };
        List<Agent> agents = jdbc.query("select a.id,a.native_kind from ai_security_artifacts a where a.active=true and "
                        + AiAgentInventoryClassification.agentSql("a")
                        + " and a.provider=:provider and a.account_id=:account and a.region=:region and a.native_kind=:kind",
                Map.of("provider", envelope.provider(), "account", envelope.accountId(), "region", envelope.region(), "kind", kind),
                (rs, n) -> new Agent(rs.getObject(1, UUID.class), rs.getString(2)));
        Map<UUID, Metadata> metadata = resolve(agents, Instant.now());
        Set<Reason> reasons = new java.util.TreeSet<>();
        metadata.values().stream().filter(m -> m.status() == Status.UNVERIFIED).forEach(m -> reasons.add(m.reasonCode()));
        String evidenceKey = "agent-deployment:" + envelope.connectorId() + ":" + envelope.resourceFamily();
        jdbc.update("update ai_grid_setup_actions set status='RESOLVED',resolved_at=now() "
                + "where category='AGENT_DEPLOYMENT' and evidence_key=:key and status='OPEN'", Map.of("key", evidenceKey));
        if (!reasons.isEmpty()) {
            String code = reasons.size() > 1 ? "VERIFY_AGENT_ROUTING_SCOPE" : switch (reasons.iterator().next()) {
                case PERMISSION_DENIED -> "GRANT_AGENT_ROUTING_READS";
                case COLLECTION_DISABLED -> "ENABLE_AGENT_ROUTING_COLLECTION";
                case BUDGET_EXHAUSTED -> "INCREASE_AGENT_ROUTING_BUDGET";
                case STALE_EVIDENCE -> "REFRESH_AGENT_ROUTING_EVIDENCE";
                default -> "VERIFY_AGENT_ROUTING_SCOPE";
            };
            setupAction(tenant, envelope.runId(), evidenceKey, code,
                    "Verify agent deployment evidence", "Connector " + envelope.connectorId() + ", family "
                            + envelope.resourceFamily() + ": " + reasons + ". Grant required read permissions, enable collection, or refresh evidence as applicable.");
        }
        Long cadence = jdbc.queryForObject("select coalesce(max(minimum_interval_seconds),0) from ai_grid_scan_cadence_rules "
                        + "where provider=:provider and resource_family=:family",
                Map.of("provider", envelope.provider(), "family", envelope.resourceFamily()), Long.class);
        Integer freshness = jdbc.queryForObject("select coalesce(max(freshness_hours),24) from ai_agent_deployment_settings", Map.of(), Integer.class);
        if (cadence != null && freshness != null && cadence > freshness * 3600L) {
            setupAction(tenant, envelope.runId(), evidenceKey, "SHORTEN_AGENT_DISCOVERY_CADENCE",
                    "Discovery cadence exceeds deployment freshness", "The minimum collection interval is " + cadence
                            + " seconds; deployment evidence expires after " + freshness + " hours. Shorten the interval. Evidence TTL was not extended.");
        }
    }

    private void setupAction(com.prototype.vulnwatch.domain.Tenant tenant, UUID run, String key, String code,
                             String title, String detail) {
        String fingerprint;
        try {
            fingerprint = java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                    .digest((tenant.getId() + "|" + key + "|" + code).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException ex) { throw new IllegalStateException(ex); }
        jdbc.update("""
                insert into ai_grid_setup_actions (id,tenant_id,run_id,fingerprint,priority,category,action_code,title,detail,evidence_key)
                values (:id,:tenant,:run,:fingerprint,50,'AGENT_DEPLOYMENT',:code,:title,:detail,:key)
                on conflict (tenant_id,fingerprint) do update set run_id=excluded.run_id,status='OPEN',resolved_at=null,
                    last_observed_at=now(),detail=excluded.detail
                """, Map.of("id", UUID.randomUUID(), "tenant", tenant.getId(), "run", run, "fingerprint", fingerprint,
                        "code", code, "title", title, "detail", detail, "key", key));
    }

    public static Metadata evaluate(Agent agent, Scope scope, List<Edge> allEdges, List<Resource> allResources,
                                    Instant now, Duration ttl) {
        Reason gap = scopeGap(scope);
        if (gap != null) return unverified(gap, scope, ttl, List.of());
        if (!now.isBefore(scope.observedAt().plus(ttl))) return unverified(Reason.STALE_EVIDENCE, scope, ttl, List.of());
        // Dataverse publication alone does not establish an enabled serving channel.
        if (agent.nativeKind().equals("MICROSOFT_COPILOT")) {
            return unverified(Reason.UNSUPPORTED_CHANNEL_EVIDENCE, scope, ttl, List.of());
        }
        List<Edge> edges = allEdges.stream().filter(e -> e.runId().equals(scope.runId())).toList();
        Map<UUID, Resource> resources = new HashMap<>();
        allResources.stream().filter(r -> r.runId().equals(scope.runId())).forEach(r -> resources.put(r.id(), r));
        boolean missingRouteIdentity = edges.stream().anyMatch(e -> e.source().equals(agent.id())
                && Set.of("HAS_COMPONENT", "HAS_DEPLOYMENT", "HAS_ENDPOINT").contains(e.type()) && !resources.containsKey(e.target()));
        if (missingRouteIdentity) return unverified(Reason.UNRESOLVED_IDENTITY, scope, ttl, List.of());
        List<UUID> routes = edges.stream().filter(e -> e.source().equals(agent.id())
                && Set.of("HAS_COMPONENT", "HAS_DEPLOYMENT", "HAS_ENDPOINT").contains(e.type()))
                .map(Edge::target).distinct().sorted().filter(id -> {
                    Resource r = resources.get(id);
                    return r != null && Set.of("AWS_BEDROCK_AGENT_ALIAS", "AWS_AGENTCORE_RUNTIME_ENDPOINT",
                            "AZURE_FOUNDRY_AGENT_ROUTES", "AZURE_FOUNDRY_AGENT_ENDPOINT", "AZURE_CLASSIC_FOUNDRY_AGENT_DEPLOYMENT").contains(r.nativeKind());
                }).toList();
        // A complete routing scope must have observed the agent identity (Bedrock emits versions instead).
        boolean identity = resources.containsKey(agent.id()) || edges.stream().anyMatch(e ->
                e.target().equals(agent.id()) && e.type().equals("VERSION_OF") && resources.containsKey(e.source()));
        if (!identity) return unverified(Reason.UNRESOLVED_IDENTITY, scope, ttl, routes);
        boolean serving = false;
        Set<Reason> gaps = new java.util.TreeSet<>();
        for (UUID id : routes) {
            Resource route = resources.get(id);
            String proofGap = route.attributes().path("deploymentEvidenceReason").asText();
            if (!proofGap.isBlank()) {
                Reason reason;
                try { reason = Reason.valueOf(proofGap); }
                catch (IllegalArgumentException ex) { reason = Reason.AMBIGUOUS_ROUTE_STATE; }
                gaps.add(validReason(Status.UNVERIFIED, reason) ? reason : Reason.AMBIGUOUS_ROUTE_STATE);
                continue;
            }
            String state = route.attributes().path("status").asText("UNKNOWN");
            if (Set.of("ZERO_TRAFFIC_ALLOCATION", "NO_ACTIVE_DEPLOYMENT", "NO_SERVING_ROUTE").contains(state)) continue;
            boolean bedrock = route.nativeKind().equals("AWS_BEDROCK_AGENT_ALIAS");
            // Bedrock's test alias routes DRAFT and is not a deployed serving version.
            if (bedrock && route.attributes().path("aliasId").asText().equals("TSTALIASID")) continue;
            String invocation = route.attributes().path("invocationState").asText();
            boolean ready = state.equals(bedrock ? "PREPARED" : "READY");
            if (!ready) { gaps.add(Reason.AMBIGUOUS_ROUTE_STATE); continue; }
            if (bedrock && invocation.equals("REJECT_INVOCATIONS")) continue;
            if (bedrock && !invocation.equals("ACCEPT_INVOCATIONS")) { gaps.add(Reason.AMBIGUOUS_ROUTE_STATE); continue; }
            List<Edge> targets = edges.stream().filter(e -> e.source().equals(id) && e.type().equals("SERVES_VERSION")).toList();
            if (targets.isEmpty()) { gaps.add(Reason.UNRESOLVED_VERSION); continue; }
            boolean resolved = targets.stream().allMatch(e -> resources.containsKey(e.target())
                    && !resources.get(e.target()).attributes().path("version").asText().equalsIgnoreCase("DRAFT")
                    && edges.stream().anyMatch(v -> v.source().equals(e.target()) && v.target().equals(agent.id())
                            && v.type().equals("VERSION_OF")));
            if (!resolved) { gaps.add(Reason.UNRESOLVED_VERSION); continue; }
            serving = true;
        }
        if (!gaps.isEmpty()) return unverified(gaps.size() == 1 ? gaps.iterator().next() : Reason.INCOMPLETE_SCOPE, scope, ttl, routes);
        Reason reason = serving ? Reason.VERIFIED_SERVING_ROUTE : switch (agent.nativeKind()) {
            case "AWS_BEDROCK_AGENT" -> Reason.NO_ALIAS_ROUTE;
            case "AWS_AGENTCORE_RUNTIME" -> Reason.NO_SERVING_ENDPOINT;
            default -> routes.stream().map(id -> resources.get(id).attributes().path("status").asText()).distinct().count() > 1
                    || routes.stream().anyMatch(id -> resources.get(id).attributes().path("status").asText().equals("NO_SERVING_ROUTE"))
                    ? Reason.NO_SERVING_ROUTE : routes.stream().anyMatch(id -> resources.get(id).attributes().path("status").asText().equals("NO_ACTIVE_DEPLOYMENT"))
                    ? Reason.NO_ACTIVE_DEPLOYMENT : routes.stream().anyMatch(id -> resources.get(id).attributes().path("status").asText().equals("ZERO_TRAFFIC_ALLOCATION"))
                    ? Reason.ZERO_TRAFFIC_ALLOCATION : Reason.NO_SERVING_ROUTE;
        };
        Status status = serving ? Status.SERVED : Status.NOT_CURRENTLY_SERVED;
        return new Metadata(status, reason, scope.observedAt(), scope.observedAt().plus(ttl),
                List.of(evidence(scope, reason, routes)), null);
    }
    static Reason scopeGap(Scope scope) {
        if (scope.status().equals("COMPLETE")) return scope.completePagination() ? null : Reason.INCOMPLETE_SCOPE;
        String diagnostic = scope.diagnostic() == null ? "" : scope.diagnostic();
        if (scope.status().equals("UNAUTHORIZED")) return Reason.PERMISSION_DENIED;
        if (diagnostic.contains("PERMISSION") || diagnostic.contains("ACCESS_DENIED")) return Reason.PERMISSION_DENIED;
        if (diagnostic.contains("BUDGET")) return Reason.BUDGET_EXHAUSTED;
        if (diagnostic.contains("DISABLED")) return Reason.COLLECTION_DISABLED;
        if (scope.status().equals("UNSUPPORTED_API")) return Reason.UNSUPPORTED_API;
        return !scope.completePagination() || scope.status().equals("PARTIAL") ? Reason.INCOMPLETE_SCOPE : Reason.PROVIDER_ERROR;
    }
    private static Evidence evidence(Scope scope, Reason reason, List<UUID> routes) {
        return new Evidence(scope.family(), scope.id(), scope.runId(), scope.observedAt(), scope.status(), reason, routes);
    }
    private static Metadata unverified(Reason reason, Scope scope, Duration ttl, List<UUID> routes) {
        return new Metadata(Status.UNVERIFIED, reason, scope == null ? null : scope.observedAt(),
                scope == null ? null : scope.observedAt().plus(ttl), scope == null ? List.of() : List.of(evidence(scope, reason, routes)), null);
    }
    private JsonNode parse(String json) {
        try { return mapper.readTree(json); }
        catch (java.io.IOException ex) { throw new IllegalStateException("Invalid immutable deployment evidence", ex); }
    }
}
