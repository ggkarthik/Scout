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
    private static final int HARD_MAX_PATHS = 10_000;
    private static final Set<String> DATA_EDGES = Set.of("USES_KNOWLEDGE_BASE", "USES_DATA_SOURCE", "READS_FROM_S3", "USES_SEARCH_INDEX");
    private static final Set<String> TOOL_EDGES = Set.of("USES_TOOL", "INVOKES_LAMBDA", "ASSUMES_ROLE", "HAS_ROLE_ASSIGNMENT", "USES_KEY_VAULT_KEY");
    private static final Set<String> MCP_EDGES = Set.of("EXPOSES_MCP", "CONNECTS_TO_MCP", "CONTAINS_MCP_TARGET");
    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectMapper objectMapper;
    private final AiGridExposureFindingService findingService;
    private final AiGridGraphEvidenceResolver graphEvidence;

    public AiGridExposureService(NamedParameterJdbcTemplate jdbc, ObjectMapper objectMapper,
                                 AiGridExposureFindingService findingService,
                                 AiGridGraphEvidenceResolver graphEvidence) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
        this.findingService = findingService;
        this.graphEvidence = graphEvidence;
    }

    public CorrelationResult correlateCompleteRun(Tenant tenant, UUID runId) {
        Instant asOf = jdbc.query("select max(observed_at) from ai_grid_snapshot_manifests where run_id=:id",
                Map.of("id", runId), rs -> rs.next() && rs.getTimestamp(1) != null ? rs.getTimestamp(1).toInstant() : null);
        if (asOf == null) return new CorrelationResult(0, 0, 0, 0, 0);
        List<Template> templates = templates();
        Map<UUID, Artifact> artifacts = artifacts(runId);
        Map<UUID, List<Edge>> graph = graph(runId, asOf);
        Map<UUID, Map<String, Fact>> facts = facts(runId, asOf);
        List<SystemContext> systems = systems(runId);
        return correlate(tenant, runId, null, asOf, templates, artifacts, graph, facts, systems, false, null, false);
    }

    /** Correlates the authoritative union of all latest complete discovery scope heads. */
    public CorrelationResult correlateCurrentEpoch(Tenant tenant, UUID epochId, UUID triggerRunId) {
        return correlateCurrentEpoch(tenant, epochId, triggerRunId, Set.of());
    }

    /** Re-evaluates only systems containing changed artifacts; an empty set performs full reconciliation. */
    public CorrelationResult correlateCurrentEpoch(Tenant tenant, UUID epochId, UUID triggerRunId,
                                                    Set<UUID> changedArtifactIds) {
        Instant asOf = jdbc.query("select materialized_at from ai_grid_current_coverage_state where epoch_id=:id",
                Map.of("id", epochId), rs -> rs.next() && rs.getTimestamp(1) != null ? rs.getTimestamp(1).toInstant() : null);
        if (asOf == null) return new CorrelationResult(0, 0, 0, 0, 0);
        List<Template> templates = templates();
        Map<UUID, Artifact> artifacts = currentArtifacts(epochId);
        Map<UUID, List<Edge>> graph = currentGraph(epochId, asOf);
        Map<UUID, Map<String, Fact>> facts = currentFacts(epochId, asOf);
        List<SystemContext> systems = currentSystems(epochId);
        boolean affectedOnly = changedArtifactIds != null && !changedArtifactIds.isEmpty();
        if (affectedOnly) systems = affectedSystems(systems, changedArtifactIds);
        String materialDigest = recordExecution(tenant, epochId, triggerRunId, asOf, templates, artifacts, graph, systems);
        return correlate(tenant, triggerRunId, epochId, asOf, templates, artifacts, graph, facts, systems,
                !affectedOnly, materialDigest, false);
    }

    private List<SystemContext> affectedSystems(List<SystemContext> systems, Set<UUID> changedArtifactIds) {
        if (systems.isEmpty()) return systems;
        Set<UUID> revisionIds = systems.stream().map(SystemContext::revisionId).collect(java.util.stream.Collectors.toSet());
        Set<UUID> affected = new HashSet<>(jdbc.query("""
                select distinct system_revision_id from ai_grid_system_memberships
                 where system_revision_id in (:revisions) and artifact_id in (:artifacts)
                """, new MapSqlParameterSource().addValue("revisions", revisionIds)
                .addValue("artifacts", changedArtifactIds), (rs, n) -> rs.getObject(1, UUID.class)));
        return systems.stream().filter(system -> affected.contains(system.revisionId())).toList();
    }

    /** Re-evaluates only the immutable inputs captured for the original execution. */
    public CorrelationResult verifyReplay(Tenant tenant, UUID triggerRunId) {
        Execution execution = jdbc.query("""
                select coverage_epoch_id,evaluation_as_of,correlation_versions_json::text,
                       artifact_bindings_json::text,relationship_ids_json::text,host_fact_ids_json::text,
                       system_revision_ids_json::text,material_digest
                  from ai_grid_exposure_executions where trigger_run_id=:runId
                 order by created_at desc limit 1
                """, Map.of("runId", triggerRunId), rs -> rs.next() ? new Execution(rs.getObject(1, UUID.class),
                rs.getTimestamp(2).toInstant(), rs.getString(3), rs.getString(4), rs.getString(5), rs.getString(6),
                rs.getString(7), rs.getString(8)) : null);
        if (execution == null) throw new IllegalArgumentException("R2 execution manifest not found for run");
        Map<UUID, UUID> bindings = uuidMap(execution.bindingsJson());
        Map<UUID, Artifact> artifacts = artifactsByIds(bindings.keySet());
        Map<UUID, List<Edge>> graph = graphByIds(uuidList(execution.relationshipIdsJson()));
        Map<UUID, Map<String, Fact>> facts = factsByBindings(bindings, uuidList(execution.hostFactIdsJson()), execution.asOf());
        List<SystemContext> systems = systemsByRevisionIds(uuidList(execution.systemRevisionIdsJson()));
        List<Template> templates = templatesByVersions(execution.versionsJson());
        return correlate(tenant, triggerRunId, execution.epochId(), execution.asOf(), templates, artifacts, graph,
                facts, systems, false, execution.materialDigest(), true);
    }

    private CorrelationResult correlate(Tenant tenant, UUID runId, UUID epochId, Instant asOf,
                                        List<Template> templates, Map<UUID, Artifact> artifacts,
                                        Map<UUID, List<Edge>> graph, Map<UUID, Map<String, Fact>> facts,
                                        List<SystemContext> systems, boolean authoritative, String materialDigest,
                                        boolean verifyOnly) {
        long started = System.nanoTime();
        Map<String, FactRule> factRules = validatingRules();
        Map<String, Candidate> candidates = new LinkedHashMap<>();
        int traversed = 0;
        for (SystemContext system : systems) {
            for (Template template : templates) {
                List<Path> paths = boundedPaths(system.rootArtifactId(), graph, artifacts, template);
                traversed += paths.size();
                for (Path path : paths) {
                    Candidate candidate = evaluate(tenant, runId, asOf, system, template, path, facts, artifacts, factRules);
                    if (candidate != null) candidates.putIfAbsent(candidate.fingerprint(), candidate);
                }
            }
        }
        int hypotheses = 0;
        int validated = 0;
        int graduated = 0;
        int demoted = 0;
        Set<String> observed = new HashSet<>();
        if (verifyOnly) {
            for (Candidate candidate : candidates.values()) {
                Integer matching = jdbc.queryForObject("""
                        select count(*) from ai_grid_exposure_paths p join ai_grid_exposure_observations o
                          on o.exposure_path_id=p.id
                         where p.fingerprint=:fingerprint and o.coverage_epoch_id=:epochId and o.state=:state
                           and o.correlation_material_digest=:digest
                        """, new MapSqlParameterSource().addValue("fingerprint", candidate.fingerprint())
                        .addValue("epochId", epochId).addValue("state", candidate.state())
                        .addValue("digest", materialDigest), Integer.class);
                if (matching == null || matching != 1)
                    throw new IllegalStateException("R2 deterministic replay mismatch for " + candidate.fingerprint());
                if ("VALIDATED_EXPOSURE".equals(candidate.state())) validated++; else hypotheses++;
            }
            return new CorrelationResult(hypotheses, validated, 0, 0, 0);
        }
        for (Candidate candidate : candidates.values()) {
            String previous = previousState(candidate.fingerprint());
            UUID exposureId = persist(tenant, candidate, epochId, materialDigest);
            observed.add(candidate.fingerprint());
            if ("VALIDATED_EXPOSURE".equals(candidate.state())) {
                validated++;
                if ("EXPOSURE_HYPOTHESIS".equals(previous)) graduated++;
                UUID findingId = findingService.reconcileValidated(tenant, candidate.finding(exposureId));
                jdbc.update("update ai_grid_exposure_paths set finding_id=:findingId where id=:id",
                        Map.of("findingId", findingId, "id", exposureId));
            } else {
                hypotheses++;
                if ("VALIDATED_EXPOSURE".equals(previous)) {
                    demoted++;
                    findingService.markNeedsEvidence(exposureId, runId);
                }
            }
        }
        int closed = closeAbsentFromCompleteRun(tenant, runId, epochId, asOf, observed, authoritative);
        recordOutbox(tenant, runId, epochId, candidates.size(), traversed);
        recordMetrics(tenant, runId, artifacts.size(), graph.values().stream().mapToInt(List::size).sum(),
                traversed, candidates.size(), java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started));
        return new CorrelationResult(hypotheses, validated, graduated, demoted, closed);
    }

    private List<Template> templates() {
        return jdbc.query("""
                select distinct on (correlation_id) correlation_id,version,name,severity,max_path_depth,max_fan_out,
                       allowed_node_types_json::text,allowed_edge_types_json::text
                  from platform.ai_grid_correlation_versions where lifecycle='PUBLISHED'
                 order by correlation_id,published_at desc,version desc
                """, (rs, n) -> new Template(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4),
                Math.min(HARD_MAX_DEPTH, rs.getInt(5)), Math.min(HARD_MAX_FAN_OUT, rs.getInt(6)),
                stringSet(rs.getString(7)), stringSet(rs.getString(8))));
    }

    private Map<UUID, Artifact> currentArtifacts(UUID epochId) {
        Map<UUID, Artifact> result = new HashMap<>();
        jdbc.query("""
                select a.id,a.artifact_type,a.name from ai_grid_current_coverage_artifacts c
                join ai_security_artifacts a on a.id=c.artifact_id where c.epoch_id=:epochId
                """, Map.of("epochId", epochId), rs -> {
            result.put(rs.getObject(1, UUID.class),
                    new Artifact(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3)));
        });
        return result;
    }

    private Map<UUID, List<Edge>> currentGraph(UUID epochId, Instant asOf) {
        Map<UUID, List<Edge>> result = new HashMap<>();
        jdbc.query("""
                select rel.id,rel.source_artifact_id,rel.target_artifact_id,rel.relationship_type,
                       rel.valid_from,rel.valid_until
                  from ai_grid_relationship_snapshots rel
                  join ai_grid_current_coverage_artifacts src on src.artifact_id=rel.source_artifact_id
                       and src.source_run_id=rel.run_id and src.epoch_id=:epochId
                  join ai_grid_current_coverage_artifacts dst on dst.artifact_id=rel.target_artifact_id
                       and dst.epoch_id=:epochId
                 where rel.valid_from<=:asOf and (rel.valid_until is null or rel.valid_until>=:asOf)
                 order by rel.source_artifact_id,rel.relationship_type,rel.target_artifact_id
                """, new MapSqlParameterSource().addValue("epochId", epochId).addValue("asOf", Timestamp.from(asOf)), rs -> {
            Edge edge = new Edge(rs.getObject(1, UUID.class), rs.getObject(2, UUID.class), rs.getObject(3, UUID.class),
                    rs.getString(4), rs.getTimestamp(5).toInstant(),
                    rs.getTimestamp(6) == null ? null : rs.getTimestamp(6).toInstant());
            result.computeIfAbsent(edge.source(), ignored -> new ArrayList<>()).add(edge);
        });
        return result;
    }

    private Map<UUID, Map<String, Fact>> currentFacts(UUID epochId, Instant asOf) {
        Map<UUID, Map<String, Fact>> result = new HashMap<>();
        jdbc.query("""
                select f.artifact_id,f.fact_key,f.value_json::text,f.state,f.provenance,f.evidence_class,f.source,
                       f.observed_at,f.observed_at valid_from,f.valid_until,f.confidence,
                       f.confidence_method,f.confidence_method_version,f.id
                  from ai_grid_current_coverage_artifacts c join ai_grid_facts f
                    on f.artifact_id=c.artifact_id and f.run_id=c.source_run_id
                 where c.epoch_id=:epochId
                union all
                select h.artifact_id,h.fact_key,h.value_json::text,h.state,h.provenance,h.evidence_class,
                       h.source_port||':'||h.evidence_reference,h.observed_at,h.valid_from,h.valid_until,
                       h.confidence,h.confidence_method,h.confidence_method_version,h.id
                  from ai_grid_host_context_facts h join ai_grid_current_coverage_artifacts c on c.artifact_id=h.artifact_id
                 where c.epoch_id=:epochId and h.observed_at<=:asOf and h.valid_from<=:asOf
                 order by observed_at desc
                """, new MapSqlParameterSource().addValue("epochId", epochId).addValue("asOf", Timestamp.from(asOf)),
                rs -> { addFact(result, rs, asOf); });
        return result;
    }

    private void addFact(Map<UUID, Map<String, Fact>> result, java.sql.ResultSet rs, Instant asOf) throws java.sql.SQLException {
        UUID artifactId = rs.getObject(1, UUID.class);
        Fact fact = new Fact(rs.getObject(14, UUID.class), rs.getString(2), tree(rs.getString(3)), rs.getString(4),
                rs.getString(5), rs.getString(6), rs.getString(7), rs.getTimestamp(8).toInstant(),
                rs.getTimestamp(9).toInstant(), rs.getTimestamp(10) == null ? null : rs.getTimestamp(10).toInstant(),
                (Double) rs.getObject(11), rs.getString(12), rs.getString(13));
        if ("KNOWN".equals(fact.state()) && !fact.validFrom().isAfter(asOf))
            result.computeIfAbsent(artifactId, ignored -> new LinkedHashMap<>()).putIfAbsent(fact.key(), fact);
    }

    private List<SystemContext> currentSystems(UUID epochId) {
        return jdbc.query("""
                select s.id,s.root_artifact_id,r.revision,r.id from ai_grid_systems s
                join ai_grid_system_revisions r on r.system_id=s.id and r.revision=s.current_revision
                where s.status='ACTIVE' and exists (select 1 from ai_grid_current_coverage_artifacts c
                       where c.epoch_id=:epochId and c.artifact_id=s.root_artifact_id) order by s.id
                """, Map.of("epochId", epochId), (rs, n) -> new SystemContext(rs.getObject(1, UUID.class),
                rs.getObject(2, UUID.class), rs.getInt(3), rs.getObject(4, UUID.class)));
    }

    private List<Template> templatesByVersions(String versionsJson) {
        Set<String> selected = new HashSet<>();
        tree(versionsJson).forEach(node -> selected.add(node.path("id").asText() + "@" + node.path("version").asText()));
        return jdbc.query("""
                select correlation_id,version,name,severity,max_path_depth,max_fan_out,
                       allowed_node_types_json::text,allowed_edge_types_json::text
                  from platform.ai_grid_correlation_versions order by correlation_id,version
                """, (rs, n) -> new Template(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4),
                Math.min(HARD_MAX_DEPTH, rs.getInt(5)), Math.min(HARD_MAX_FAN_OUT, rs.getInt(6)),
                stringSet(rs.getString(7)), stringSet(rs.getString(8)))).stream()
                .filter(t -> selected.contains(t.id() + "@" + t.version())).toList();
    }

    private Map<UUID, Artifact> artifactsByIds(Set<UUID> ids) {
        if (ids.isEmpty()) return Map.of();
        Map<UUID, Artifact> result = new HashMap<>();
        jdbc.query("select id,artifact_type,name from ai_security_artifacts where id in (:ids)",
                Map.of("ids", ids), rs -> {
            result.put(rs.getObject(1, UUID.class), new Artifact(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3)));
        });
        return result;
    }

    private Map<UUID, List<Edge>> graphByIds(List<UUID> ids) {
        if (ids.isEmpty()) return Map.of();
        Map<UUID, List<Edge>> result = new HashMap<>();
        jdbc.query("""
                select id,source_artifact_id,target_artifact_id,relationship_type,valid_from,valid_until
                  from ai_grid_relationship_snapshots where id in (:ids)
                 order by source_artifact_id,relationship_type,target_artifact_id
                """, Map.of("ids", ids), rs -> {
            Edge edge = new Edge(rs.getObject(1, UUID.class), rs.getObject(2, UUID.class), rs.getObject(3, UUID.class),
                    rs.getString(4), rs.getTimestamp(5).toInstant(),
                    rs.getTimestamp(6) == null ? null : rs.getTimestamp(6).toInstant());
            result.computeIfAbsent(edge.source(), ignored -> new ArrayList<>()).add(edge);
        });
        return result;
    }

    private Map<UUID, Map<String, Fact>> factsByBindings(Map<UUID, UUID> bindings, List<UUID> hostIds, Instant asOf) {
        Map<UUID, Map<String, Fact>> result = new HashMap<>();
        if (!bindings.isEmpty()) jdbc.query("""
                select artifact_id,fact_key,value_json::text,state,provenance,evidence_class,source,
                       observed_at,observed_at valid_from,valid_until,confidence,
                       confidence_method,confidence_method_version,id,run_id
                  from ai_grid_facts where artifact_id in (:ids) order by observed_at desc
                """, Map.of("ids", bindings.keySet()), rs -> {
            UUID artifactId = rs.getObject(1, UUID.class);
            if (bindings.get(artifactId).equals(rs.getObject(15, UUID.class))) addFact(result, rs, asOf);
        });
        if (!hostIds.isEmpty()) jdbc.query("""
                select artifact_id,fact_key,value_json::text,state,provenance,evidence_class,
                       source_port||':'||evidence_reference,observed_at,valid_from,valid_until,
                       confidence,confidence_method,confidence_method_version,id
                  from ai_grid_host_context_facts where id in (:ids)
                 order by observed_at desc
                """, Map.of("ids", hostIds), rs -> { addFact(result, rs, asOf); });
        return result;
    }

    private List<SystemContext> systemsByRevisionIds(List<UUID> ids) {
        if (ids.isEmpty()) return List.of();
        return jdbc.query("""
                select s.id,s.root_artifact_id,r.revision,r.id from ai_grid_system_revisions r
                join ai_grid_systems s on s.id=r.system_id where r.id in (:ids) order by s.id
                """, Map.of("ids", ids), (rs, n) -> new SystemContext(rs.getObject(1, UUID.class),
                rs.getObject(2, UUID.class), rs.getInt(3), rs.getObject(4, UUID.class)));
    }

    private Map<UUID, UUID> uuidMap(String json) {
        Map<UUID, UUID> result = new HashMap<>();
        tree(json).fields().forEachRemaining(e -> result.put(UUID.fromString(e.getKey()), UUID.fromString(e.getValue().asText())));
        return result;
    }

    private List<UUID> uuidList(String json) {
        List<UUID> result = new ArrayList<>();
        tree(json).forEach(n -> result.add(UUID.fromString(n.asText())));
        return result;
    }

    private String recordExecution(Tenant tenant, UUID epochId, UUID triggerRunId, Instant asOf,
                                   List<Template> templates, Map<UUID, Artifact> artifacts,
                                   Map<UUID, List<Edge>> graph, List<SystemContext> systems) {
        Map<String, String> bindings = new java.util.TreeMap<>();
        jdbc.query("select artifact_id,source_run_id from ai_grid_current_coverage_artifacts where epoch_id=:id order by artifact_id",
                Map.of("id", epochId), rs -> {
            bindings.put(rs.getObject(1, UUID.class).toString(), rs.getObject(2, UUID.class).toString());
        });
        List<Map<String, String>> versions = templates.stream().map(t -> Map.of("id", t.id(), "version", t.version())).toList();
        List<String> edgeIds = graph.values().stream().flatMap(List::stream).map(e -> e.id().toString()).sorted().toList();
        List<String> hostFactIds = jdbc.query("""
                select h.id::text from ai_grid_host_context_facts h
                join ai_grid_current_coverage_artifacts c on c.artifact_id=h.artifact_id
                 where c.epoch_id=:epochId and h.observed_at<=:asOf and h.valid_from<=:asOf order by h.id
                """, new MapSqlParameterSource().addValue("epochId", epochId).addValue("asOf", Timestamp.from(asOf)),
                (rs, n) -> rs.getString(1));
        List<String> revisionIds = systems.stream().map(s -> s.revisionId().toString()).sorted().toList();
        Map<String, Object> material = new LinkedHashMap<>();
        material.put("versions", versions); material.put("bindings", bindings); material.put("edges", edgeIds);
        material.put("hostFacts", hostFactIds); material.put("systemRevisions", revisionIds); material.put("asOf", asOf);
        String digest = sha256(json(material));
        jdbc.update("""
                insert into ai_grid_exposure_executions
                    (id,tenant_id,coverage_epoch_id,trigger_run_id,evaluation_as_of,correlation_versions_json,
                     artifact_bindings_json,relationship_ids_json,host_fact_ids_json,system_revision_ids_json,material_digest)
                values (:id,:tenantId,:epochId,:runId,:asOf,cast(:versions as jsonb),cast(:bindings as jsonb),
                        cast(:edges as jsonb),cast(:facts as jsonb),cast(:revisions as jsonb),:digest)
                on conflict (tenant_id,coverage_epoch_id) do nothing
                """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                .addValue("epochId", epochId).addValue("runId", triggerRunId).addValue("asOf", Timestamp.from(asOf))
                .addValue("versions", json(versions)).addValue("bindings", json(bindings)).addValue("edges", json(edgeIds))
                .addValue("facts", json(hostFactIds)).addValue("revisions", json(revisionIds)).addValue("digest", digest));
        String persisted = jdbc.queryForObject("select material_digest from ai_grid_exposure_executions where coverage_epoch_id=:id",
                Map.of("id", epochId), String.class);
        if (!digest.equals(persisted)) throw new IllegalStateException("Coverage epoch correlation inputs changed after capture");
        return digest;
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
        graphEvidence.graphForRun(runId, asOf).forEach(value -> {
            Edge edge = new Edge(value.id(), value.sourceArtifactId(), value.targetArtifactId(), value.type(),
                    value.validFrom(), value.validUntil());
            result.computeIfAbsent(edge.source(), ignored -> new ArrayList<>()).add(edge);
        });
        return result;
    }

    private Map<UUID, Map<String, Fact>> facts(UUID runId, Instant asOf) {
        Map<UUID, Map<String, Fact>> result = new HashMap<>();
        jdbc.query("""
                select artifact_id,fact_key,value_json::text,state,provenance,evidence_class,source,
                       observed_at,observed_at valid_from,valid_until,confidence,
                       confidence_method,confidence_method_version,id
                  from ai_grid_facts where run_id=:runId
                union all
                select artifact_id,fact_key,value_json::text,state,provenance,evidence_class,
                       source_port||':'||evidence_reference,observed_at,valid_from,valid_until,
                       confidence,confidence_method,confidence_method_version,id
                  from ai_grid_host_context_facts
                 where observed_at<=:asOf and valid_from<=:asOf
                order by observed_at desc
                """, new MapSqlParameterSource().addValue("runId", runId).addValue("asOf", Timestamp.from(asOf)), rs -> {
            UUID artifactId = rs.getObject(1, UUID.class);
            Fact fact = new Fact(rs.getObject(14, UUID.class), rs.getString(2), tree(rs.getString(3)), rs.getString(4),
                    rs.getString(5), rs.getString(6), rs.getString(7), rs.getTimestamp(8).toInstant(),
                    rs.getTimestamp(9).toInstant(), rs.getTimestamp(10) == null ? null : rs.getTimestamp(10).toInstant(),
                    (Double) rs.getObject(11), rs.getString(12), rs.getString(13));
            if ("KNOWN".equals(fact.state()) && !fact.validFrom().isAfter(asOf))
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
        while (!queue.isEmpty()) {
            Path path = queue.removeFirst();
            if (!path.edges().isEmpty()) result.add(path);
            if (result.size() >= HARD_MAX_PATHS) break;
            if (path.edges().size() >= template.maxDepth()) continue;
            UUID source = path.nodes().get(path.nodes().size() - 1);
            List<Edge> edges = graph.getOrDefault(source, List.of()).stream()
                    .filter(edge -> template.edgeTypes().contains(edge.type()))
                    .filter(edge -> artifacts.containsKey(edge.target()))
                    .filter(edge -> template.nodeTypes().contains(artifacts.get(edge.target()).type()))
                    .sorted(Comparator.comparing(Edge::type).thenComparing(edge -> edge.target().toString()))
                    .limit(template.maxFanOut()).toList();
            for (Edge edge : edges) {
                if (path.nodes().contains(edge.target())) continue;
                List<UUID> nodes = new ArrayList<>(path.nodes()); nodes.add(edge.target());
                List<Edge> nextEdges = new ArrayList<>(path.edges()); nextEdges.add(edge);
                queue.addLast(new Path(List.copyOf(nodes), List.copyOf(nextEdges)));
            }
        }
        return result;
    }

    private Candidate evaluate(Tenant tenant, UUID runId, Instant asOf, SystemContext system, Template template,
                               Path path, Map<UUID, Map<String, Fact>> facts, Map<UUID, Artifact> artifacts,
                               Map<String, FactRule> factRules) {
        boolean validated;
        boolean hypothesis;
        UUID rootCause;
        String impact;
        String breakpoint;
        switch (template.id()) {
            case "R2_EXTERNAL_SENSITIVE_ACCESS" -> {
                validated = exactTrueOn(path.nodes().get(0), facts, "network.internet_reachability_verified", factRules, asOf)
                        && exactTrueOn(path.nodes().get(0), facts, "identity.inadequate_authentication_verified", factRules, asOf)
                        && exactTrueOn(path.nodes().get(path.nodes().size() - 1), facts, "data.sensitive_access_confirmed", factRules, asOf)
                        && hasEdge(path, DATA_EDGES);
                hypothesis = (hasTrue(path, facts, "network.public_access_configured", asOf)
                        && hasInadequateAuthProxy(path, facts, asOf)
                        && (hasTrue(path, facts, "data.source_linked", asOf) || hasEdge(path, DATA_EDGES)))
                        || (hasEdge(path, DATA_EDGES)
                        && rawTrueOn(path.nodes().get(0), facts, "network.internet_reachability_verified")
                        && rawTrueOn(path.nodes().get(0), facts, "identity.inadequate_authentication_verified")
                        && rawTrueOn(path.nodes().get(path.nodes().size() - 1), facts, "data.sensitive_access_confirmed")
                        && hasStale(path, facts, asOf, Set.of("network.internet_reachability_verified",
                        "identity.inadequate_authentication_verified", "data.sensitive_access_confirmed")));
                rootCause = artifactWith(path, facts, "identity.inadequate_authentication_verified",
                        artifactWith(path, facts, "network.public_access_configured", system.rootArtifactId()));
                impact = "External access may reach an AI-connected sensitive data source.";
                breakpoint = "Remove external reachability or require strong identity authentication before sensitive-data access.";
            }
            case "R2_EXCESSIVE_TOOL_PRIVILEGE" -> {
                boolean toolEnabledAgent = "AI_AGENT".equals(artifacts.get(path.nodes().get(0)).type())
                        && hasEdge(path, Set.of("USES_TOOL", "INVOKES_LAMBDA"));
                validated = toolEnabledAgent && hasDerivedTrue(path, facts, "identity.effective_excessive_privilege_derived", factRules, asOf)
                        && exactTrueOn(path.nodes().get(path.nodes().size() - 1), facts,
                        "impact.secret_or_consequential_access_confirmed", factRules, asOf);
                hypothesis = toolEnabledAgent && (hasTrue(path, facts, "identity.wildcard_permission_observed", asOf)
                        || (hasRawTrue(path, facts, "identity.effective_excessive_privilege_derived")
                        && rawTrueOn(path.nodes().get(path.nodes().size() - 1), facts,
                        "impact.secret_or_consequential_access_confirmed")
                        && hasStale(path, facts, asOf, Set.of("identity.effective_excessive_privilege_derived",
                        "impact.secret_or_consequential_access_confirmed"))));
                rootCause = artifactWith(path, facts, "identity.effective_excessive_privilege_derived", system.rootArtifactId());
                impact = "A tool-enabled agent may exercise secret access or consequential actions with excessive privilege.";
                breakpoint = "Reduce effective privileges and place approval boundaries around consequential tool actions.";
            }
            case "R2_UNTRUSTED_AUTONOMOUS_EXECUTION" -> {
                validated = exactTrueOn(path.nodes().get(path.nodes().size() - 1), facts, "input.untrusted_path_verified", factRules, asOf)
                        && exactTrueOn(path.nodes().get(0), facts, "agent.autonomous_execution_verified", factRules, asOf)
                        && exactTrueOn(path.nodes().get(0), facts, "control.execution_boundary_inadequate_verified", factRules, asOf)
                        && (hasEdge(path, DATA_EDGES) || hasEdge(path, TOOL_EDGES));
                hypothesis = (hasEdge(path, DATA_EDGES) && hasAutonomousProxy(path, facts, asOf)
                        && hasWeakControlProxy(path, facts, asOf))
                        || ((hasEdge(path, DATA_EDGES) || hasEdge(path, TOOL_EDGES))
                        && rawTrueOn(path.nodes().get(path.nodes().size() - 1), facts, "input.untrusted_path_verified")
                        && rawTrueOn(path.nodes().get(0), facts, "agent.autonomous_execution_verified")
                        && rawTrueOn(path.nodes().get(0), facts, "control.execution_boundary_inadequate_verified")
                        && hasStale(path, facts, asOf, Set.of("input.untrusted_path_verified",
                        "agent.autonomous_execution_verified", "control.execution_boundary_inadequate_verified")));
                rootCause = artifactWith(path, facts, "control.execution_boundary_inadequate_verified", system.rootArtifactId());
                impact = "Untrusted input may influence autonomous execution without an adequate control boundary.";
                breakpoint = "Add verified guardrail, isolation, or human approval before autonomous execution.";
            }
            case "R2_EXTERNAL_MCP_SENSITIVE_ACCESS" -> {
                validated = hasEdge(path, MCP_EDGES)
                        && exactTrueOn(path.nodes().get(0), facts, "mcp.external_or_unapproved_verified", factRules, asOf)
                        && exactTrueOn(path.nodes().get(path.nodes().size() - 1), facts, "data.sensitive_access_confirmed", factRules, asOf);
                hypothesis = hasEdge(path, MCP_EDGES) && hasWeakMcpAuthentication(path, facts, asOf)
                        && (hasTrue(path, facts, "data.source_linked", asOf) || hasEdge(path, DATA_EDGES));
                rootCause = artifactWith(path, facts, "mcp.external_or_unapproved_verified", system.rootArtifactId());
                impact = "An externally reachable or unapproved MCP path may reach sensitive data.";
                breakpoint = "Approve the MCP endpoint, require strong authentication, or remove the sensitive-data path.";
            }
            case "R2_MCP_WEAK_AUTH_EXECUTION" -> {
                validated = hasEdge(path, MCP_EDGES)
                        && exactTrueOn(path.nodes().get(0), facts, "agent.autonomous_execution_verified", factRules, asOf)
                        && exactTrueOn(path.nodes().get(path.nodes().size() - 1), facts, "mcp.auth_inadequate_verified", factRules, asOf);
                hypothesis = hasEdge(path, MCP_EDGES) && hasAutonomousProxy(path, facts, asOf)
                        && hasWeakMcpAuthentication(path, facts, asOf);
                rootCause = artifactWith(path, facts, "mcp.auth_inadequate_verified", system.rootArtifactId());
                impact = "High-impact execution may route through an MCP target without reliable authentication.";
                breakpoint = "Require verified MCP target authentication before permitting autonomous or high-impact execution.";
            }
            case "R2_SENSITIVE_RETRIEVAL_CONTROL_GAP" -> {
                validated = hasEdge(path, DATA_EDGES)
                        && exactTrueOn(path.nodes().get(path.nodes().size() - 1), facts, "data.sensitive_access_confirmed", factRules, asOf)
                        && exactTrueOn(path.nodes().get(0), facts, "control.execution_boundary_inadequate_verified", factRules, asOf);
                hypothesis = hasEdge(path, DATA_EDGES) && hasWeakControlProxy(path, facts, asOf)
                        && (hasTrue(path, facts, "data.source_linked", asOf) || hasTrue(path, facts, "data.sensitive_access_confirmed", asOf));
                rootCause = artifactWith(path, facts, "control.execution_boundary_inadequate_verified", system.rootArtifactId());
                impact = "An AI retrieval path may access sensitive data without the required guardrail or PII-filter baseline.";
                breakpoint = "Apply and verify the guardrail or PII-filter baseline before sensitive retrieval.";
            }
            default -> { return null; }
        }
        List<Fact> validatingEvidence = validatingEvidence(path, facts, template.id());
        boolean signalsPresent = validatingEvidence.size() == requiredEvidenceCount(template.id())
                && validatingEvidence.stream().allMatch(f -> truthy(f.value()));
        if (validated && !meetsConfidenceRequirements(template.id(), validatingEvidence)) {
            validated = false;
            hypothesis = true;
        } else if (!validated && signalsPresent) {
            hypothesis = true;
        }
        if (!validated && !hypothesis) return null;
        String state = validated ? "VALIDATED_EXPOSURE" : "EXPOSURE_HYPOTHESIS";
        String signature = pathSignature(path);
        String fingerprint = sha256(tenant.getId() + "|AI_EXPOSURE|" + template.id() + "|" + rootCause + "|" + signature);
        List<Fact> evidenceFacts = evidenceFacts(path, facts, template.id(), validated);
        double confidence = validated ? validatingEvidence.stream().map(Fact::confidence)
                .filter(java.util.Objects::nonNull).mapToDouble(Double::doubleValue).min().orElse(0.0) : 0.60;
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

    private UUID persist(Tenant tenant, Candidate candidate, UUID epochId, String materialDigest) {
        Instant now = Instant.now();
        UUID exposureId = jdbc.queryForObject("""
                insert into ai_grid_exposure_paths
                    (id,tenant_id,fingerprint,correlation_id,correlation_version,root_cause_artifact_id,
                     canonical_path_signature,state,status,severity,title,impact,root_cause,breakpoint,
                     confidence_method,confidence_method_version,confidence,first_observed_at,last_observed_at,
                     validated_at,closed_at,last_complete_run_id,last_complete_epoch_id)
                values (:id,:tenantId,:fingerprint,:correlationId,:version,:rootCause,:signature,:state,'OPEN',
                        :severity,:title,:impact,:rootCauseText,:breakpoint,'TEMPLATE_EXACT_EVIDENCE','1.0.0',
                        :confidence,:now,:now,case when cast(:state as varchar)='VALIDATED_EXPOSURE'
                            then cast(:now as timestamptz) else null::timestamptz end,null,:runId,:epochId)
                on conflict (tenant_id,fingerprint) do update set correlation_version=excluded.correlation_version,
                    state=excluded.state,status='OPEN',severity=excluded.severity,title=excluded.title,
                    impact=excluded.impact,root_cause=excluded.root_cause,breakpoint=excluded.breakpoint,
                    confidence=excluded.confidence,last_observed_at=excluded.last_observed_at,
                    validated_at=case when excluded.state='VALIDATED_EXPOSURE'
                        then coalesce(ai_grid_exposure_paths.validated_at,excluded.validated_at)
                        else ai_grid_exposure_paths.validated_at end,
                    closed_at=null,last_complete_run_id=excluded.last_complete_run_id,
                    last_complete_epoch_id=excluded.last_complete_epoch_id,updated_at=now()
                returning id
                """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                .addValue("fingerprint", candidate.fingerprint()).addValue("correlationId", candidate.template().id())
                .addValue("version", candidate.template().version()).addValue("rootCause", candidate.rootCause())
                .addValue("signature", pathSignature(candidate.path())).addValue("state", candidate.state())
                .addValue("severity", candidate.template().severity()).addValue("title", candidate.template().name())
                .addValue("impact", candidate.impact()).addValue("rootCauseText", candidate.rootCauseText())
                .addValue("breakpoint", candidate.breakpoint()).addValue("confidence", candidate.confidence())
                .addValue("now", Timestamp.from(now)).addValue("runId", candidate.runId())
                .addValue("epochId", epochId), UUID.class);
        jdbc.update("""
                insert into ai_grid_exposure_observations
                    (id,tenant_id,exposure_path_id,run_id,state,entry_artifact_id,system_id,system_revision_id,
                     path_json,evidence_json,temporal_valid_from,temporal_valid_until,confidence,
                     coverage_epoch_id,correlation_material_digest)
                values (:id,:tenantId,:exposureId,:runId,:state,:entry,:systemId,:revisionId,
                        cast(:path as jsonb),cast(:evidence as jsonb),:validFrom,:validUntil,:confidence,:epochId,:digest)
                on conflict (tenant_id,exposure_path_id,run_id,coverage_epoch_id) do update set state=excluded.state,
                    path_json=excluded.path_json,evidence_json=excluded.evidence_json,
                    temporal_valid_from=excluded.temporal_valid_from,temporal_valid_until=excluded.temporal_valid_until,
                    confidence=excluded.confidence,coverage_epoch_id=excluded.coverage_epoch_id,
                    correlation_material_digest=excluded.correlation_material_digest,observed_at=now()
                """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                .addValue("exposureId", exposureId).addValue("runId", candidate.runId()).addValue("state", candidate.state())
                .addValue("entry", candidate.path().nodes().get(0)).addValue("systemId", candidate.system().id())
                .addValue("revisionId", candidate.system().revisionId()).addValue("path", json(pathView(candidate.path())))
                .addValue("evidence", json(candidate.evidence()))
                .addValue("validFrom", Timestamp.from(candidate.validFrom()))
                .addValue("validUntil", candidate.validUntil() == null ? null : Timestamp.from(candidate.validUntil()))
                .addValue("confidence", candidate.confidence()).addValue("epochId", epochId)
                .addValue("digest", materialDigest));
        associate(tenant, exposureId, candidate.system(), null, "AFFECTED_SYSTEM");
        associate(tenant, exposureId, null, candidate.path().nodes().get(0), "ENTRY_POINT");
        associate(tenant, exposureId, null, candidate.rootCause(), "ROOT_CAUSE");
        associate(tenant, exposureId, null, candidate.path().nodes().get(candidate.path().nodes().size() - 1), "IMPACT");
        return exposureId;
    }

    private int closeAbsentFromCompleteRun(Tenant tenant, UUID runId, UUID epochId, Instant asOf,
                                           Set<String> observed, boolean authoritative) {
        List<OpenExposure> open = authoritative ? jdbc.query("""
                select p.id,p.fingerprint,p.finding_id from ai_grid_exposure_paths p where p.status='OPEN'
                """, (rs, n) -> new OpenExposure(rs.getObject(1, UUID.class), rs.getString(2),
                rs.getObject(3, UUID.class))) : jdbc.query("""
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
                        last_complete_run_id=:runId,last_complete_epoch_id=:epochId,updated_at=now() where id=:id
                    """, new MapSqlParameterSource().addValue("asOf", Timestamp.from(asOf)).addValue("runId", runId)
                    .addValue("epochId", epochId).addValue("id", exposure.id()));
            jdbc.update("""
                    insert into ai_grid_exposure_observations
                        (id,tenant_id,exposure_path_id,run_id,state,path_json,evidence_json,
                         temporal_valid_from,confidence,coverage_epoch_id,correlation_material_digest)
                    values (:id,:tenantId,:exposureId,:runId,'ABSENT','[]'::jsonb,
                            '{"closure":"COMPLETE_REASSESSMENT_PATH_ABSENT"}'::jsonb,:asOf,1.0,:epochId,
                            (select material_digest from ai_grid_exposure_executions where coverage_epoch_id=:epochId))
                    on conflict (tenant_id,exposure_path_id,run_id,coverage_epoch_id) do nothing
                    """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                    .addValue("exposureId", exposure.id()).addValue("runId", runId)
                    .addValue("epochId", epochId)
                    .addValue("asOf", Timestamp.from(asOf)));
            Integer remaining = exposure.findingId() == null ? 0 : jdbc.queryForObject("""
                    select count(*) from ai_grid_exposure_paths
                     where finding_id=:findingId and status='OPEN' and id<>:id
                    """, Map.of("findingId", exposure.findingId(), "id", exposure.id()), Integer.class);
            if (remaining == null || remaining == 0)
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

    private void recordOutbox(Tenant tenant, UUID runId, UUID epochId, int paths, int traversed) {
        jdbc.update("""
                insert into ai_grid_outbox (id,tenant_id,event_type,aggregate_type,aggregate_id,aggregate_version,payload_json)
                values (:id,:tenantId,'GRAPH_SUBJECT_CHANGED','ASSESSMENT_RUN',:runId,:version,cast(:payload as jsonb))
                on conflict do nothing
                """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                .addValue("runId", runId).addValue("version", epochId == null ? "run-r2-v1" : epochId.toString())
                .addValue("payload", json(Map.of("exposurePaths", paths, "traversedPaths", traversed,
                        "coverageEpochId", epochId == null ? "RUN_SCOPED" : epochId.toString()))));
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
    private boolean exactTrueOn(UUID artifactId, Map<UUID, Map<String, Fact>> facts, String key,
                                Map<String, FactRule> rules, Instant asOf) {
        Fact fact = facts.getOrDefault(artifactId, Map.of()).get(key);
        return fact != null && truthy(fact.value()) && qualifies(fact, rules.get(key), asOf);
    }
    private boolean hasDerivedTrue(Path path, Map<UUID, Map<String, Fact>> facts, String key,
                                   Map<String, FactRule> rules, Instant asOf) {
        return path.nodes().stream().map(id -> facts.getOrDefault(id, Map.of()).get(key))
                .anyMatch(f -> f != null && truthy(f.value()) && "DERIVED".equals(f.provenance())
                        && qualifies(f, rules.get(key), asOf));
    }
    private boolean hasTrue(Path path, Map<UUID, Map<String, Fact>> facts, String key, Instant asOf) {
        return path.nodes().stream().map(id -> facts.getOrDefault(id, Map.of()).get(key))
                .anyMatch(f -> f != null && truthy(f.value())
                        && (f.validUntil() == null || !f.validUntil().isBefore(asOf)));
    }
    private boolean rawTrueOn(UUID artifactId, Map<UUID, Map<String, Fact>> facts, String key) {
        Fact fact = facts.getOrDefault(artifactId, Map.of()).get(key);
        return fact != null && truthy(fact.value());
    }
    private boolean hasRawTrue(Path path, Map<UUID, Map<String, Fact>> facts, String key) {
        return path.nodes().stream().anyMatch(id -> rawTrueOn(id, facts, key));
    }
    private boolean hasStale(Path path, Map<UUID, Map<String, Fact>> facts, Instant asOf, Set<String> keys) {
        return path.nodes().stream().flatMap(id -> facts.getOrDefault(id, Map.of()).values().stream())
                .anyMatch(f -> keys.contains(f.key()) && f.validUntil() != null && f.validUntil().isBefore(asOf));
    }
    private Map<String, FactRule> validatingRules() {
        Map<String, FactRule> result = new HashMap<>();
        jdbc.query("""
                select distinct on (fact_key) fact_key,allowed_evidence_classes_json::text,default_max_age_seconds
                  from platform.ai_grid_fact_definitions where lifecycle='ACTIVE'
                 order by fact_key,version desc
                """, rs -> {
            result.put(rs.getString(1), new FactRule(stringSet(rs.getString(2)), rs.getLong(3)));
        });
        return result;
    }
    private boolean qualifies(Fact fact, FactRule rule, Instant asOf) {
        return rule != null && rule.evidenceClasses().contains(fact.evidenceClass()) && fact.validUntil() != null
                && !fact.validUntil().isBefore(asOf)
                && !fact.observedAt().isBefore(asOf.minusSeconds(rule.maxAgeSeconds()))
                && fact.confidence() != null && fact.confidenceMethod() != null
                && !fact.confidenceMethod().isBlank() && fact.confidenceMethodVersion() != null
                && !fact.confidenceMethodVersion().isBlank()
                && !"ANALYST_ATTESTED".equals(fact.provenance());
    }

    private boolean meetsConfidenceRequirements(String correlationId, List<Fact> evidence) {
        if (evidence.size() != requiredEvidenceCount(correlationId)) return false;
        double minimum = switch (correlationId) {
            case "R2_EXTERNAL_SENSITIVE_ACCESS" -> 0.95;
            case "R2_EXCESSIVE_TOOL_PRIVILEGE", "R2_MCP_WEAK_AUTH_EXECUTION" -> 0.93;
            case "R2_UNTRUSTED_AUTONOMOUS_EXECUTION", "R2_SENSITIVE_RETRIEVAL_CONTROL_GAP" -> 0.92;
            case "R2_EXTERNAL_MCP_SENSITIVE_ACCESS" -> 0.95;
            default -> 1.0;
        };
        return evidence.stream().allMatch(f -> f.confidence() != null && f.confidence() >= minimum
                && f.confidenceMethod() != null && !f.confidenceMethod().isBlank()
                && f.confidenceMethodVersion() != null && !f.confidenceMethodVersion().isBlank()
                && !"ANALYST_ATTESTED".equals(f.provenance()));
    }

    private int requiredEvidenceCount(String correlationId) {
        return switch (correlationId) {
            case "R2_EXCESSIVE_TOOL_PRIVILEGE", "R2_EXTERNAL_MCP_SENSITIVE_ACCESS",
                    "R2_MCP_WEAK_AUTH_EXECUTION", "R2_SENSITIVE_RETRIEVAL_CONTROL_GAP" -> 2;
            default -> 3;
        };
    }

    private List<Fact> validatingEvidence(Path path, Map<UUID, Map<String, Fact>> facts, String correlationId) {
        Set<String> keys = switch (correlationId) {
            case "R2_EXTERNAL_SENSITIVE_ACCESS" -> Set.of("network.internet_reachability_verified",
                    "identity.inadequate_authentication_verified", "data.sensitive_access_confirmed");
            case "R2_EXCESSIVE_TOOL_PRIVILEGE" -> Set.of("identity.effective_excessive_privilege_derived",
                    "impact.secret_or_consequential_access_confirmed");
            case "R2_UNTRUSTED_AUTONOMOUS_EXECUTION" -> Set.of("input.untrusted_path_verified",
                    "agent.autonomous_execution_verified", "control.execution_boundary_inadequate_verified");
            case "R2_EXTERNAL_MCP_SENSITIVE_ACCESS" -> Set.of("mcp.external_or_unapproved_verified",
                    "data.sensitive_access_confirmed");
            case "R2_MCP_WEAK_AUTH_EXECUTION" -> Set.of("agent.autonomous_execution_verified",
                    "mcp.auth_inadequate_verified");
            case "R2_SENSITIVE_RETRIEVAL_CONTROL_GAP" -> Set.of("data.sensitive_access_confirmed",
                    "control.execution_boundary_inadequate_verified");
            default -> Set.of();
        };
        return path.nodes().stream().flatMap(id -> facts.getOrDefault(id, Map.of()).values().stream())
                .filter(f -> keys.contains(f.key())).distinct().toList();
    }
    private boolean hasInadequateAuthProxy(Path path, Map<UUID, Map<String, Fact>> facts, Instant asOf) {
        if (List.of("identity.local_auth_enabled_configured", "identity.ml_endpoint_local_auth_enabled_configured",
                "identity.search_local_admin_auth_enabled_configured", "identity.bot_password_without_managed_identity_observed")
                .stream().anyMatch(key -> hasTrue(path, facts, key, asOf))) return true;
        return path.nodes().stream().map(id -> facts.getOrDefault(id, Map.of()).get("compute.lambda_url_auth_type_configured"))
                .anyMatch(f -> f != null && "NONE".equalsIgnoreCase(f.value().asText())
                        && (f.validUntil() == null || !f.validUntil().isBefore(asOf)));
    }
    private boolean hasAutonomousProxy(Path path, Map<UUID, Map<String, Fact>> facts, Instant asOf) {
        return hasTrue(path, facts, "agent.code_interpreter_enabled_configured", asOf) || hasEdge(path, TOOL_EDGES);
    }
    private boolean hasWeakControlProxy(Path path, Map<UUID, Map<String, Fact>> facts, Instant asOf) {
        return path.nodes().stream().map(id -> facts.getOrDefault(id, Map.of()).get("bedrock.agent.guardrail_attached_configured"))
                .anyMatch(f -> f != null && !truthy(f.value()) && (f.validUntil() == null || !f.validUntil().isBefore(asOf)))
                || path.nodes().stream().map(id -> facts.getOrDefault(id, Map.of()).get("bedrock.guardrail.minimum_strength_configured"))
                .anyMatch(f -> f != null && Set.of("NONE", "LOW").contains(f.value().asText().toUpperCase())
                        && (f.validUntil() == null || !f.validUntil().isBefore(asOf)));
    }
    private boolean hasWeakMcpAuthentication(Path path, Map<UUID, Map<String, Fact>> facts, Instant asOf) {
        return List.of("mcp.configured_auth_type", "mcp.inbound_auth_type", "mcp.outbound_auth_type").stream()
                .map(key -> path.nodes().stream().map(id -> facts.getOrDefault(id, Map.of()).get(key)))
                .flatMap(java.util.function.Function.identity())
                .anyMatch(f -> f != null && Set.of("NONE", "UNKNOWN", "").contains(f.value().asText().toUpperCase())
                        && (f.validUntil() == null || !f.validUntil().isBefore(asOf)));
    }
    private boolean hasEdge(Path path, Set<String> types) { return path.edges().stream().anyMatch(e -> types.contains(e.type())); }
    private UUID artifactWith(Path path, Map<UUID, Map<String, Fact>> facts, String key, UUID fallback) {
        return path.nodes().stream().filter(id -> facts.getOrDefault(id, Map.of()).containsKey(key)).findFirst().orElse(fallback);
    }
    private List<Fact> evidenceFacts(Path path, Map<UUID, Map<String, Fact>> facts,
                                     String correlationId, boolean validated) {
        Set<String> keys = switch (correlationId) {
            case "R2_EXTERNAL_SENSITIVE_ACCESS" -> Set.of(
                    "network.internet_reachability_verified", "identity.inadequate_authentication_verified",
                    "data.sensitive_access_confirmed", "network.public_access_configured", "identity.local_auth_enabled_configured",
                    "identity.ml_endpoint_local_auth_enabled_configured", "identity.search_local_admin_auth_enabled_configured",
                    "identity.bot_password_without_managed_identity_observed", "compute.lambda_url_auth_type_configured",
                    "data.source_linked");
            case "R2_EXCESSIVE_TOOL_PRIVILEGE" -> Set.of("identity.effective_excessive_privilege_derived",
                    "impact.secret_or_consequential_access_confirmed", "identity.wildcard_permission_observed");
            case "R2_UNTRUSTED_AUTONOMOUS_EXECUTION" -> Set.of(
                    "input.untrusted_path_verified", "agent.autonomous_execution_verified",
                    "control.execution_boundary_inadequate_verified", "data.source_linked", "agent.code_interpreter_enabled_configured",
                    "bedrock.agent.guardrail_attached_configured", "bedrock.guardrail.minimum_strength_configured");
            case "R2_EXTERNAL_MCP_SENSITIVE_ACCESS" -> Set.of("mcp.external_or_unapproved_verified",
                    "data.sensitive_access_confirmed", "mcp.configured_auth_type", "mcp.inbound_auth_type",
                    "mcp.outbound_auth_type", "data.source_linked");
            case "R2_MCP_WEAK_AUTH_EXECUTION" -> Set.of("agent.autonomous_execution_verified",
                    "mcp.auth_inadequate_verified", "agent.code_interpreter_enabled_configured", "mcp.configured_auth_type",
                    "mcp.inbound_auth_type", "mcp.outbound_auth_type");
            case "R2_SENSITIVE_RETRIEVAL_CONTROL_GAP" -> Set.of("data.sensitive_access_confirmed",
                    "control.execution_boundary_inadequate_verified", "data.source_linked",
                    "bedrock.agent.guardrail_attached_configured", "bedrock.guardrail.minimum_strength_configured",
                    "guardrail.rai_non_blocking_filter_observed");
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
                        String source, Instant observedAt, Instant validFrom, Instant validUntil, Double confidence,
                        String confidenceMethod, String confidenceMethodVersion) {}
    private record FactRule(Set<String> evidenceClasses, long maxAgeSeconds) {}
    private record Path(List<UUID> nodes, List<Edge> edges) {}
    private record SystemContext(UUID id, UUID rootArtifactId, int revision, UUID revisionId) {}
    private record OpenExposure(UUID id, String fingerprint, UUID findingId) {}
    private record Execution(UUID epochId, Instant asOf, String versionsJson, String bindingsJson,
                             String relationshipIdsJson, String hostFactIdsJson,
                             String systemRevisionIdsJson, String materialDigest) {}
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
