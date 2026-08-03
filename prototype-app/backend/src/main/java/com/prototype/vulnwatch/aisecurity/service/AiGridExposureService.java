package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.aisecurity.service.AiGridExposureFindingService.ExposureFinding;
import com.prototype.vulnwatch.domain.Tenant;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

/** Versioned, bounded R2 correlation engine. It consumes only stored run snapshots and host-context ports. */
@Service
public class AiGridExposureService {
    private static final int HARD_MAX_DEPTH = 6;
    private static final int HARD_MAX_FAN_OUT = 100;
    private static final Set<String> DATA_EDGES = Set.of("USES_KNOWLEDGE_BASE", "USES_DATA_SOURCE", "READS_FROM_S3", "USES_SEARCH_INDEX");
    private static final Set<String> TOOL_EDGES = Set.of("USES_TOOL", "INVOKES_LAMBDA", "ASSUMES_ROLE", "HAS_ROLE_ASSIGNMENT", "USES_KEY_VAULT_KEY");
    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectMapper objectMapper;
    private final AiGridExposureFindingService findingService;

    public AiGridExposureService(NamedParameterJdbcTemplate jdbc, ObjectMapper objectMapper,
                                 AiGridExposureFindingService findingService) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
        this.findingService = findingService;
    }

    public CorrelationResult correlateCompleteRun(Tenant tenant, UUID runId) {
        long started = System.nanoTime();
        Instant asOf = jdbc.query("select max(observed_at) from ai_grid_snapshot_manifests where run_id=:id",
                Map.of("id", runId), rs -> rs.next() && rs.getTimestamp(1) != null ? rs.getTimestamp(1).toInstant() : null);
        if (asOf == null) return new CorrelationResult(0, 0, 0, 0, 0);
        List<Template> templates = templates();
        Map<UUID, Artifact> artifacts = artifacts(runId);
        Map<UUID, List<Edge>> graph = graph(runId, asOf);
        Map<UUID, Map<String, Fact>> facts = facts(runId, asOf);
        List<SystemContext> systems = systems(runId);
        Map<String, Candidate> candidates = new LinkedHashMap<>();
        int traversed = 0;
        for (SystemContext system : systems) {
            for (Template template : templates) {
                List<Path> paths = boundedPaths(system.rootArtifactId(), graph, artifacts, template);
                traversed += paths.size();
                for (Path path : paths) {
                    Candidate candidate = evaluate(tenant, runId, asOf, system, template, path, facts);
                    if (candidate != null) candidates.putIfAbsent(candidate.fingerprint(), candidate);
                }
            }
        }
        int hypotheses = 0;
        int validated = 0;
        int graduated = 0;
        int demoted = 0;
        Set<String> observed = new HashSet<>();
        for (Candidate candidate : candidates.values()) {
            String previous = previousState(candidate.fingerprint());
            UUID exposureId = persist(tenant, candidate);
            observed.add(candidate.fingerprint());
            if ("VALIDATED_EXPOSURE".equals(candidate.state())) {
                validated++;
                if ("EXPOSURE_HYPOTHESIS".equals(previous)) graduated++;
                UUID findingId = findingService.reconcileValidated(tenant, candidate.finding(exposureId));
                jdbc.update("update ai_grid_exposure_paths set finding_id=:findingId where id=:id",
                        Map.of("findingId", findingId, "id", exposureId));
            } else {
                hypotheses++;
                if ("VALIDATED_EXPOSURE".equals(previous)) demoted++;
            }
        }
        int closed = closeAbsentFromCompleteRun(tenant, runId, asOf, observed);
        recordOutbox(tenant, runId, candidates.size(), traversed);
        recordMetrics(tenant, runId, artifacts.size(), graph.values().stream().mapToInt(List::size).sum(),
                traversed, candidates.size(), java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started));
        return new CorrelationResult(hypotheses, validated, graduated, demoted, closed);
    }

    private List<Template> templates() {
        return jdbc.query("""
                select correlation_id,version,name,severity,max_path_depth,max_fan_out,
                       allowed_node_types_json::text,allowed_edge_types_json::text
                  from platform.ai_grid_correlation_versions where lifecycle='PUBLISHED'
                 order by correlation_id,version
                """, (rs, n) -> new Template(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4),
                Math.min(HARD_MAX_DEPTH, rs.getInt(5)), Math.min(HARD_MAX_FAN_OUT, rs.getInt(6)),
                stringSet(rs.getString(7)), stringSet(rs.getString(8))));
    }

    private Map<UUID, Artifact> artifacts(UUID runId) {
        Map<UUID, Artifact> result = new HashMap<>();
        jdbc.query("""
                select distinct a.id,a.artifact_type,a.name from ai_security_artifacts a
                join ai_security_artifact_sources s on s.artifact_id=a.id where s.run_id=:runId
                """, Map.of("runId", runId), rs -> {
            result.put(rs.getObject(1, UUID.class),
                    new Artifact(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3)));
        });
        return result;
    }

    private Map<UUID, List<Edge>> graph(UUID runId, Instant asOf) {
        Map<UUID, List<Edge>> result = new HashMap<>();
        jdbc.query("""
                select id,source_artifact_id,target_artifact_id,relationship_type,valid_from,valid_until
                  from ai_grid_relationship_snapshots where run_id=:runId
                   and valid_from<=:asOf and (valid_until is null or valid_until>=:asOf)
                 order by source_artifact_id,relationship_type,target_artifact_id
                """, new MapSqlParameterSource().addValue("runId", runId).addValue("asOf", Timestamp.from(asOf)), rs -> {
            Edge edge = new Edge(rs.getObject(1, UUID.class), rs.getObject(2, UUID.class),
                    rs.getObject(3, UUID.class), rs.getString(4), rs.getTimestamp(5).toInstant(),
                    rs.getTimestamp(6) == null ? null : rs.getTimestamp(6).toInstant());
            result.computeIfAbsent(edge.source(), ignored -> new ArrayList<>()).add(edge);
        });
        return result;
    }

    private Map<UUID, Map<String, Fact>> facts(UUID runId, Instant asOf) {
        Map<UUID, Map<String, Fact>> result = new HashMap<>();
        jdbc.query("""
                select artifact_id,fact_key,value_json::text,state,provenance,evidence_class,source,
                       observed_at,observed_at valid_from,valid_until,coalesce(confidence,1.0),id
                  from ai_grid_facts where run_id=:runId
                union all
                select artifact_id,fact_key,value_json::text,state,provenance,evidence_class,
                       source_port||':'||evidence_reference,observed_at,valid_from,valid_until,
                       coalesce(confidence,1.0),id
                  from ai_grid_host_context_facts
                 where valid_from<=:asOf and (valid_until is null or valid_until>=:asOf)
                order by observed_at desc
                """, new MapSqlParameterSource().addValue("runId", runId).addValue("asOf", Timestamp.from(asOf)), rs -> {
            UUID artifactId = rs.getObject(1, UUID.class);
            Fact fact = new Fact(rs.getObject(12, UUID.class), rs.getString(2), tree(rs.getString(3)), rs.getString(4),
                    rs.getString(5), rs.getString(6), rs.getString(7), rs.getTimestamp(8).toInstant(),
                    rs.getTimestamp(9).toInstant(), rs.getTimestamp(10) == null ? null : rs.getTimestamp(10).toInstant(),
                    rs.getDouble(11));
            if ("KNOWN".equals(fact.state()) && !fact.validFrom().isAfter(asOf)
                    && (fact.validUntil() == null || !fact.validUntil().isBefore(asOf)))
                result.computeIfAbsent(artifactId, ignored -> new LinkedHashMap<>()).putIfAbsent(fact.key(), fact);
        });
        return result;
    }

    private List<SystemContext> systems(UUID runId) {
        return jdbc.query("""
                select distinct s.id,s.root_artifact_id,s.current_revision,r.id
                  from ai_grid_systems s join ai_grid_system_revisions r
                    on r.system_id=s.id and r.revision=s.current_revision
                  join ai_security_artifact_sources src on src.artifact_id=s.root_artifact_id and src.run_id=:runId
                 where s.status='ACTIVE' and s.root_artifact_id is not null order by s.id
                """, Map.of("runId", runId), (rs, n) -> new SystemContext(rs.getObject(1, UUID.class),
                rs.getObject(2, UUID.class), rs.getInt(3), rs.getObject(4, UUID.class)));
    }

    private List<Path> boundedPaths(UUID root, Map<UUID, List<Edge>> graph, Map<UUID, Artifact> artifacts, Template template) {
        List<Path> result = new ArrayList<>();
        ArrayDeque<Path> queue = new ArrayDeque<>();
        queue.add(new Path(List.of(root), List.of()));
        Set<UUID> expanded = new HashSet<>();
        expanded.add(root);
        while (!queue.isEmpty()) {
            Path path = queue.removeFirst();
            if (!path.edges().isEmpty()) result.add(path);
            if (path.edges().size() >= template.maxDepth()) continue;
            UUID source = path.nodes().get(path.nodes().size() - 1);
            List<Edge> edges = graph.getOrDefault(source, List.of()).stream()
                    .filter(edge -> template.edgeTypes().contains(edge.type()))
                    .filter(edge -> artifacts.containsKey(edge.target()))
                    .filter(edge -> template.nodeTypes().contains(artifacts.get(edge.target()).type()))
                    .sorted(Comparator.comparing(Edge::type).thenComparing(edge -> edge.target().toString()))
                    .limit(template.maxFanOut()).toList();
            for (Edge edge : edges) {
                if (!expanded.add(edge.target())) continue;
                List<UUID> nodes = new ArrayList<>(path.nodes()); nodes.add(edge.target());
                List<Edge> nextEdges = new ArrayList<>(path.edges()); nextEdges.add(edge);
                queue.addLast(new Path(List.copyOf(nodes), List.copyOf(nextEdges)));
            }
        }
        return result;
    }

    private Candidate evaluate(Tenant tenant, UUID runId, Instant asOf, SystemContext system, Template template,
                               Path path, Map<UUID, Map<String, Fact>> facts) {
        boolean validated;
        boolean hypothesis;
        UUID rootCause;
        String impact;
        String breakpoint;
        switch (template.id()) {
            case "R2_EXTERNAL_SENSITIVE_ACCESS" -> {
                validated = hasExactTrue(path, facts, "network.internet_reachability_verified")
                        && hasExactTrue(path, facts, "identity.inadequate_authentication_verified")
                        && hasExactTrue(path, facts, "data.sensitive_access_confirmed") && hasEdge(path, DATA_EDGES);
                hypothesis = hasTrue(path, facts, "network.public_access_configured")
                        && hasInadequateAuthProxy(path, facts) && (hasTrue(path, facts, "data.source_linked") || hasEdge(path, DATA_EDGES));
                rootCause = artifactWith(path, facts, "identity.inadequate_authentication_verified",
                        artifactWith(path, facts, "network.public_access_configured", system.rootArtifactId()));
                impact = "External access may reach an AI-connected sensitive data source.";
                breakpoint = "Remove external reachability or require strong identity authentication before sensitive-data access.";
            }
            case "R2_EXCESSIVE_TOOL_PRIVILEGE" -> {
                validated = hasDerivedTrue(path, facts, "identity.effective_excessive_privilege_derived")
                        && hasExactTrue(path, facts, "impact.secret_or_consequential_access_confirmed") && hasEdge(path, TOOL_EDGES);
                hypothesis = hasEdge(path, TOOL_EDGES) && hasTrue(path, facts, "identity.wildcard_permission_observed");
                rootCause = artifactWith(path, facts, "identity.effective_excessive_privilege_derived", system.rootArtifactId());
                impact = "A tool-enabled agent may exercise secret access or consequential actions with excessive privilege.";
                breakpoint = "Reduce effective privileges and place approval boundaries around consequential tool actions.";
            }
            case "R2_UNTRUSTED_AUTONOMOUS_EXECUTION" -> {
                validated = hasExactTrue(path, facts, "input.untrusted_path_verified")
                        && hasExactTrue(path, facts, "agent.autonomous_execution_verified")
                        && hasExactTrue(path, facts, "control.execution_boundary_inadequate_verified")
                        && (hasEdge(path, DATA_EDGES) || hasEdge(path, TOOL_EDGES));
                hypothesis = hasEdge(path, DATA_EDGES) && hasAutonomousProxy(path, facts) && hasWeakControlProxy(path, facts);
                rootCause = artifactWith(path, facts, "control.execution_boundary_inadequate_verified", system.rootArtifactId());
                impact = "Untrusted input may influence autonomous execution without an adequate control boundary.";
                breakpoint = "Add verified guardrail, isolation, or human approval before autonomous execution.";
            }
            default -> { return null; }
        }
        if (!validated && !hypothesis) return null;
        String state = validated ? "VALIDATED_EXPOSURE" : "EXPOSURE_HYPOTHESIS";
        String signature = pathSignature(path);
        String fingerprint = sha256(tenant.getId() + "|AI_EXPOSURE|" + template.id() + "|" + rootCause + "|" + signature);
        List<Fact> evidenceFacts = evidenceFacts(path, facts, template.id(), validated);
        double confidence = validated ? evidenceFacts.stream().mapToDouble(Fact::confidence).min().orElse(1.0) : 0.60;
        Instant validFrom = java.util.stream.Stream.concat(path.edges().stream().map(Edge::validFrom),
                        evidenceFacts.stream().map(Fact::validFrom))
                .max(Instant::compareTo).orElse(asOf);
        Instant validUntil = java.util.stream.Stream.concat(path.edges().stream().map(Edge::validUntil),
                        evidenceFacts.stream().map(Fact::validUntil))
                .filter(java.util.Objects::nonNull).min(Instant::compareTo).orElse(null);
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("factIds", evidenceFacts.stream().map(Fact::id).toList());
        evidence.put("edgeIds", path.edges().stream().map(Edge::id).toList());
        evidence.put("asOf", asOf);
        evidence.put("exactEvidence", validated);
        evidence.put("freshnessChecked", true);
        return new Candidate(runId, fingerprint, template, system, path, rootCause, state, confidence,
                impact, "The path contains the template's qualifying control weakness.", breakpoint,
                validFrom, validUntil, evidence);
    }

    private UUID persist(Tenant tenant, Candidate candidate) {
        Instant now = Instant.now();
        UUID exposureId = jdbc.queryForObject("""
                insert into ai_grid_exposure_paths
                    (id,tenant_id,fingerprint,correlation_id,correlation_version,root_cause_artifact_id,
                     canonical_path_signature,state,status,severity,title,impact,root_cause,breakpoint,
                     confidence_method,confidence_method_version,confidence,first_observed_at,last_observed_at,
                     validated_at,closed_at,last_complete_run_id)
                values (:id,:tenantId,:fingerprint,:correlationId,:version,:rootCause,:signature,:state,'OPEN',
                        :severity,:title,:impact,:rootCauseText,:breakpoint,'TEMPLATE_EXACT_EVIDENCE','1.0.0',
                        :confidence,:now,:now,case when cast(:state as varchar)='VALIDATED_EXPOSURE'
                            then cast(:now as timestamptz) else null::timestamptz end,null,:runId)
                on conflict (tenant_id,fingerprint) do update set correlation_version=excluded.correlation_version,
                    state=excluded.state,status='OPEN',severity=excluded.severity,title=excluded.title,
                    impact=excluded.impact,root_cause=excluded.root_cause,breakpoint=excluded.breakpoint,
                    confidence=excluded.confidence,last_observed_at=excluded.last_observed_at,
                    validated_at=case when excluded.state='VALIDATED_EXPOSURE'
                        then coalesce(ai_grid_exposure_paths.validated_at,excluded.validated_at)
                        else ai_grid_exposure_paths.validated_at end,
                    closed_at=null,last_complete_run_id=excluded.last_complete_run_id,updated_at=now()
                returning id
                """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                .addValue("fingerprint", candidate.fingerprint()).addValue("correlationId", candidate.template().id())
                .addValue("version", candidate.template().version()).addValue("rootCause", candidate.rootCause())
                .addValue("signature", pathSignature(candidate.path())).addValue("state", candidate.state())
                .addValue("severity", candidate.template().severity()).addValue("title", candidate.template().name())
                .addValue("impact", candidate.impact()).addValue("rootCauseText", candidate.rootCauseText())
                .addValue("breakpoint", candidate.breakpoint()).addValue("confidence", candidate.confidence())
                .addValue("now", Timestamp.from(now)).addValue("runId", candidate.runId()), UUID.class);
        jdbc.update("""
                insert into ai_grid_exposure_observations
                    (id,tenant_id,exposure_path_id,run_id,state,entry_artifact_id,system_id,system_revision_id,
                     path_json,evidence_json,temporal_valid_from,temporal_valid_until,confidence)
                values (:id,:tenantId,:exposureId,:runId,:state,:entry,:systemId,:revisionId,
                        cast(:path as jsonb),cast(:evidence as jsonb),:validFrom,:validUntil,:confidence)
                on conflict (tenant_id,exposure_path_id,run_id) do update set state=excluded.state,
                    path_json=excluded.path_json,evidence_json=excluded.evidence_json,
                    temporal_valid_from=excluded.temporal_valid_from,temporal_valid_until=excluded.temporal_valid_until,
                    confidence=excluded.confidence,observed_at=now()
                """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                .addValue("exposureId", exposureId).addValue("runId", candidate.runId()).addValue("state", candidate.state())
                .addValue("entry", candidate.path().nodes().get(0)).addValue("systemId", candidate.system().id())
                .addValue("revisionId", candidate.system().revisionId()).addValue("path", json(pathView(candidate.path())))
                .addValue("evidence", json(candidate.evidence()))
                .addValue("validFrom", Timestamp.from(candidate.validFrom()))
                .addValue("validUntil", candidate.validUntil() == null ? null : Timestamp.from(candidate.validUntil()))
                .addValue("confidence", candidate.confidence()));
        associate(tenant, exposureId, candidate.system(), null, "AFFECTED_SYSTEM");
        associate(tenant, exposureId, null, candidate.path().nodes().get(0), "ENTRY_POINT");
        associate(tenant, exposureId, null, candidate.rootCause(), "ROOT_CAUSE");
        associate(tenant, exposureId, null, candidate.path().nodes().get(candidate.path().nodes().size() - 1), "IMPACT");
        return exposureId;
    }

    private int closeAbsentFromCompleteRun(Tenant tenant, UUID runId, Instant asOf, Set<String> observed) {
        List<OpenExposure> open = jdbc.query("""
                select p.id,p.fingerprint,p.finding_id from ai_grid_exposure_paths p
                 where p.status='OPEN' and exists (
                     select 1 from ai_security_artifact_sources s
                      where s.run_id=:runId and s.artifact_id=p.root_cause_artifact_id)
                """, Map.of("runId", runId), (rs, n) -> new OpenExposure(rs.getObject(1, UUID.class),
                rs.getString(2), rs.getObject(3, UUID.class)));
        int closed = 0;
        for (OpenExposure exposure : open) {
            if (observed.contains(exposure.fingerprint())) continue;
            jdbc.update("""
                    update ai_grid_exposure_paths set state='CLOSED',status='CLOSED',closed_at=:asOf,
                        last_complete_run_id=:runId,updated_at=now() where id=:id
                    """, Map.of("asOf", Timestamp.from(asOf), "runId", runId, "id", exposure.id()));
            jdbc.update("""
                    insert into ai_grid_exposure_observations
                        (id,tenant_id,exposure_path_id,run_id,state,path_json,evidence_json,
                         temporal_valid_from,confidence)
                    values (:id,:tenantId,:exposureId,:runId,'ABSENT','[]'::jsonb,
                            '{"closure":"COMPLETE_REASSESSMENT_PATH_ABSENT"}'::jsonb,:asOf,1.0)
                    on conflict (tenant_id,exposure_path_id,run_id) do nothing
                    """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                    .addValue("exposureId", exposure.id()).addValue("runId", runId)
                    .addValue("asOf", Timestamp.from(asOf)));
            findingService.closeVerified(tenant, exposure.findingId(), runId, exposure.id());
            closed++;
        }
        return closed;
    }

    private void associate(Tenant tenant, UUID exposureId, SystemContext system, UUID artifactId, String role) {
        jdbc.update("""
                insert into ai_grid_exposure_associations
                    (id,tenant_id,exposure_path_id,system_id,system_revision_id,artifact_id,association_role)
                values (:id,:tenantId,:exposureId,:systemId,:revisionId,:artifactId,:role) on conflict do nothing
                """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                .addValue("exposureId", exposureId).addValue("systemId", system == null ? null : system.id())
                .addValue("revisionId", system == null ? null : system.revisionId()).addValue("artifactId", artifactId)
                .addValue("role", role));
    }

    private String previousState(String fingerprint) {
        List<String> states = jdbc.query("select state from ai_grid_exposure_paths where fingerprint=:f",
                Map.of("f", fingerprint), (rs, n) -> rs.getString(1));
        return states.isEmpty() ? null : states.get(0);
    }

    private void recordOutbox(Tenant tenant, UUID runId, int paths, int traversed) {
        jdbc.update("""
                insert into ai_grid_outbox (id,tenant_id,event_type,aggregate_type,aggregate_id,aggregate_version,payload_json)
                values (:id,:tenantId,'GRAPH_SUBJECT_CHANGED','ASSESSMENT_RUN',:runId,'r2-v1',cast(:payload as jsonb))
                on conflict do nothing
                """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                .addValue("runId", runId).addValue("payload", json(Map.of("exposurePaths", paths, "traversedPaths", traversed))));
    }

    private void recordMetrics(Tenant tenant, UUID runId, long nodes, long edges, long traversed,
                               long exposurePaths, long durationMs) {
        jdbc.update("""
                insert into ai_grid_run_metrics
                    (run_id,tenant_id,graph_recomputed_node_count,graph_recomputed_edge_count,
                     graph_traversed_path_count,exposure_path_count,graph_recompute_duration_ms)
                values (:runId,:tenantId,:nodes,:edges,:traversed,:paths,:duration)
                on conflict (run_id) do update set
                    graph_recomputed_node_count=excluded.graph_recomputed_node_count,
                    graph_recomputed_edge_count=excluded.graph_recomputed_edge_count,
                    graph_traversed_path_count=excluded.graph_traversed_path_count,
                    exposure_path_count=excluded.exposure_path_count,
                    graph_recompute_duration_ms=excluded.graph_recompute_duration_ms,updated_at=now()
                """, Map.of("runId", runId, "tenantId", tenant.getId(), "nodes", nodes, "edges", edges,
                "traversed", traversed, "paths", exposurePaths, "duration", durationMs));
    }

    private boolean hasExactTrue(Path path, Map<UUID, Map<String, Fact>> facts, String key) {
        return path.nodes().stream().map(id -> facts.getOrDefault(id, Map.of()).get(key))
                .anyMatch(f -> f != null && truthy(f.value()) && !"CONFIGURATION".equals(f.evidenceClass()));
    }
    private boolean hasDerivedTrue(Path path, Map<UUID, Map<String, Fact>> facts, String key) {
        return path.nodes().stream().map(id -> facts.getOrDefault(id, Map.of()).get(key))
                .anyMatch(f -> f != null && truthy(f.value()) && "DERIVED".equals(f.provenance()));
    }
    private boolean hasTrue(Path path, Map<UUID, Map<String, Fact>> facts, String key) {
        return path.nodes().stream().map(id -> facts.getOrDefault(id, Map.of()).get(key))
                .anyMatch(f -> f != null && truthy(f.value()));
    }
    private boolean hasInadequateAuthProxy(Path path, Map<UUID, Map<String, Fact>> facts) {
        if (List.of("identity.local_auth_enabled_configured", "identity.ml_endpoint_local_auth_enabled_configured",
                "identity.search_local_admin_auth_enabled_configured", "identity.bot_password_without_managed_identity_observed")
                .stream().anyMatch(key -> hasTrue(path, facts, key))) return true;
        return path.nodes().stream().map(id -> facts.getOrDefault(id, Map.of()).get("compute.lambda_url_auth_type_configured"))
                .anyMatch(f -> f != null && "NONE".equalsIgnoreCase(f.value().asText()));
    }
    private boolean hasAutonomousProxy(Path path, Map<UUID, Map<String, Fact>> facts) {
        return hasTrue(path, facts, "agent.code_interpreter_enabled_configured") || hasEdge(path, TOOL_EDGES);
    }
    private boolean hasWeakControlProxy(Path path, Map<UUID, Map<String, Fact>> facts) {
        return path.nodes().stream().map(id -> facts.getOrDefault(id, Map.of()).get("bedrock.agent.guardrail_attached_configured"))
                .anyMatch(f -> f != null && !truthy(f.value()))
                || path.nodes().stream().map(id -> facts.getOrDefault(id, Map.of()).get("bedrock.guardrail.minimum_strength_configured"))
                .anyMatch(f -> f != null && Set.of("NONE", "LOW").contains(f.value().asText().toUpperCase()));
    }
    private boolean hasEdge(Path path, Set<String> types) { return path.edges().stream().anyMatch(e -> types.contains(e.type())); }
    private UUID artifactWith(Path path, Map<UUID, Map<String, Fact>> facts, String key, UUID fallback) {
        return path.nodes().stream().filter(id -> facts.getOrDefault(id, Map.of()).containsKey(key)).findFirst().orElse(fallback);
    }
    private List<Fact> evidenceFacts(Path path, Map<UUID, Map<String, Fact>> facts,
                                     String correlationId, boolean validated) {
        Set<String> keys = switch (correlationId) {
            case "R2_EXTERNAL_SENSITIVE_ACCESS" -> validated
                    ? Set.of("network.internet_reachability_verified", "identity.inadequate_authentication_verified",
                    "data.sensitive_access_confirmed")
                    : Set.of("network.public_access_configured", "identity.local_auth_enabled_configured",
                    "identity.ml_endpoint_local_auth_enabled_configured", "identity.search_local_admin_auth_enabled_configured",
                    "identity.bot_password_without_managed_identity_observed", "compute.lambda_url_auth_type_configured",
                    "data.source_linked");
            case "R2_EXCESSIVE_TOOL_PRIVILEGE" -> validated
                    ? Set.of("identity.effective_excessive_privilege_derived", "impact.secret_or_consequential_access_confirmed")
                    : Set.of("identity.wildcard_permission_observed");
            case "R2_UNTRUSTED_AUTONOMOUS_EXECUTION" -> validated
                    ? Set.of("input.untrusted_path_verified", "agent.autonomous_execution_verified",
                    "control.execution_boundary_inadequate_verified")
                    : Set.of("data.source_linked", "agent.code_interpreter_enabled_configured",
                    "bedrock.agent.guardrail_attached_configured", "bedrock.guardrail.minimum_strength_configured");
            default -> Set.of();
        };
        return path.nodes().stream().flatMap(id -> facts.getOrDefault(id, Map.of()).values().stream())
                .filter(fact -> keys.contains(fact.key()))
                .sorted(Comparator.comparing(Fact::key).thenComparing(f -> f.id().toString())).toList();
    }
    private String pathSignature(Path path) {
        List<String> parts = new ArrayList<>(); parts.add(path.nodes().get(0).toString());
        for (Edge edge : path.edges()) { parts.add(edge.type()); parts.add(edge.target().toString()); }
        return sha256(String.join("|", parts));
    }
    private List<Map<String, Object>> pathView(Path path) {
        List<Map<String, Object>> view = new ArrayList<>();
        for (int i = 0; i < path.nodes().size(); i++) {
            Map<String, Object> node = new LinkedHashMap<>(); node.put("artifactId", path.nodes().get(i)); node.put("position", i);
            if (i > 0) node.put("incomingEdge", path.edges().get(i - 1).type());
            view.add(node);
        }
        return view;
    }
    private boolean truthy(JsonNode value) { return value != null && (value.isBoolean() ? value.asBoolean() : "true".equalsIgnoreCase(value.asText())); }
    private Set<String> stringSet(String json) {
        try { Set<String> result = new LinkedHashSet<>(); objectMapper.readTree(json).forEach(n -> result.add(n.asText())); return result; }
        catch (Exception e) { throw new IllegalArgumentException("Invalid correlation type list", e); }
    }
    private JsonNode tree(String json) {
        try { return objectMapper.readTree(json); } catch (Exception e) { throw new IllegalArgumentException("Invalid fact JSON", e); }
    }
    private String json(Object value) {
        try { return objectMapper.writeValueAsString(value); } catch (Exception e) { throw new IllegalArgumentException("Invalid exposure JSON", e); }
    }
    private String sha256(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (Exception e) { throw new IllegalStateException("Unable to hash exposure identity", e); }
    }

    public record CorrelationResult(int hypotheses, int validated, int graduated, int demoted, int closed) {}
    private record Template(String id, String version, String name, String severity, int maxDepth, int maxFanOut,
                            Set<String> nodeTypes, Set<String> edgeTypes) {}
    private record Artifact(UUID id, String type, String name) {}
    private record Edge(UUID id, UUID source, UUID target, String type, Instant validFrom, Instant validUntil) {}
    private record Fact(UUID id, String key, JsonNode value, String state, String provenance, String evidenceClass,
                        String source, Instant observedAt, Instant validFrom, Instant validUntil, double confidence) {}
    private record Path(List<UUID> nodes, List<Edge> edges) {}
    private record SystemContext(UUID id, UUID rootArtifactId, int revision, UUID revisionId) {}
    private record OpenExposure(UUID id, String fingerprint, UUID findingId) {}
    private record Candidate(UUID runId, String fingerprint, Template template, SystemContext system, Path path,
                             UUID rootCause, String state, double confidence, String impact, String rootCauseText,
                             String breakpoint, Instant validFrom, Instant validUntil, Map<String, Object> evidence) {
        ExposureFinding finding(UUID exposureId) {
            return new ExposureFinding(exposureId, runId, fingerprint, template.id(), template.version(), template.name(),
                    template.severity(), confidence, system.id(), system.revision(), path.nodes().get(0), rootCause,
                    path, evidence);
        }
    }
}
