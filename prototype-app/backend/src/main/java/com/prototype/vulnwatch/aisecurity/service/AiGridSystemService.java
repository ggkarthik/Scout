package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

/** Builds immutable, agent-rooted AI-system revisions from a run-scoped relationship graph. */
@Service
public class AiGridSystemService {
    static final int MAX_DEPTH = 6;
    static final int MAX_FAN_OUT = 100;
    private static final Set<String> MEMBERSHIP_EDGES = Set.of(
            "USES_GUARDRAIL", "USES_KNOWLEDGE_BASE", "USES_MODEL", "USES_DATA_SOURCE",
            "INVOKES_LAMBDA", "ASSUMES_ROLE", "READS_FROM_S3", "SUPERVISES_AGENT",
            "CONTAINS_PROJECT", "DEPLOYS_MODEL", "USES_TOOL", "USES_SEARCH_INDEX",
            "USES_MANAGED_IDENTITY", "USES_KEY_VAULT_KEY", "CONTAINS_RESOURCE",
            "HAS_DEPLOYMENT", "RUNS_PIPELINE", "HAS_CHANNEL", "HAS_ROLE_ASSIGNMENT");

    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectMapper objectMapper;

    public AiGridSystemService(NamedParameterJdbcTemplate jdbc, ObjectMapper objectMapper) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
    }

    public void deriveForRun(Tenant tenant, UUID runId) {
        List<Agent> agents = jdbc.query("""
                select distinct a.id, a.provider, a.provider_resource_id, a.name
                  from ai_security_artifacts a
                  join ai_security_artifact_sources s on s.artifact_id = a.id
                 where s.run_id = :runId and a.active = true
                   and a.artifact_type in ('AI_AGENT','AI_MODEL','KNOWLEDGE_BASE','OTHER_AI_ARTIFACT')
                   and (a.artifact_type='AI_AGENT' or not exists (
                       select 1 from ai_grid_relationship_snapshots incoming
                        where incoming.run_id=:runId and incoming.target_artifact_id=a.id
                          and incoming.relationship_type in (:membershipEdges)))
                """, new MapSqlParameterSource().addValue("runId", runId)
                .addValue("membershipEdges", MEMBERSHIP_EDGES), (rs, n) -> new Agent(rs.getObject("id", UUID.class),
                rs.getString("provider"), rs.getString("provider_resource_id"), rs.getString("name")));
        Map<UUID, List<Edge>> graph = relationshipGraph(runId);
        List<UUID> derivedSystems = new ArrayList<>();
        for (Agent agent : agents) {
            List<UUID> members = boundedMembers(agent.id(), graph);
            String stableKey = sha256(tenant.getId() + "|" + agent.provider() + "|" + agent.providerResourceId());
            UUID systemId = jdbc.queryForObject("""
                    insert into ai_grid_systems (id, tenant_id, stable_key, name, root_artifact_id, status, retired_at)
                    values (:id, :tenantId, :stableKey, :name, :rootId, 'ACTIVE', null)
                    on conflict (tenant_id, stable_key) do update set name = excluded.name,
                        root_artifact_id = excluded.root_artifact_id, status = 'ACTIVE', retired_at = null, updated_at = now()
                    returning id
                    """, new MapSqlParameterSource().addValue("id", UUID.randomUUID())
                    .addValue("tenantId", tenant.getId()).addValue("stableKey", stableKey)
                    .addValue("name", agent.name()).addValue("rootId", agent.id()), UUID.class);
            derivedSystems.add(systemId);
            members = applyOverrides(systemId, members);
            createRevisionIfChanged(tenant, runId, null, systemId, members, "DETERMINISTIC",
                    "Bounded run-scoped provider relationship graph for the agent root", null);
        }
        retireRunRootsNoLongerSystems(tenant, runId, derivedSystems);
        retireInactiveRoots(tenant, runId);
    }

    /** Derives systems from the deletion-safe union of the latest complete scope heads. */
    public void deriveForCurrentEpoch(Tenant tenant, UUID epochId, UUID triggerRunId) {
        Instant asOf = currentEpochAsOf(epochId);
        Map<UUID, Set<UUID>> previous = activeSystemMembers();
        List<Agent> roots = jdbc.query("""
                select a.id,a.provider,a.provider_resource_id,a.name
                  from ai_grid_current_coverage_artifacts c join ai_security_artifacts a on a.id=c.artifact_id
                 where c.epoch_id=:epochId and a.active=true
                   and a.artifact_type in ('AI_AGENT','AI_MODEL','KNOWLEDGE_BASE','OTHER_AI_ARTIFACT')
                   and (a.artifact_type='AI_AGENT' or not exists (
                       select 1 from ai_grid_relationship_snapshots rel
                       join ai_grid_current_coverage_artifacts src on src.artifact_id=rel.source_artifact_id
                            and src.source_run_id=rel.run_id and src.epoch_id=:epochId
                       join ai_grid_current_coverage_artifacts dst on dst.artifact_id=rel.target_artifact_id
                            and dst.epoch_id=:epochId
                        where rel.target_artifact_id=a.id and rel.relationship_type in (:membershipEdges)
                          and rel.valid_from<=:asOf and (rel.valid_until is null or rel.valid_until>=:asOf)))
                 order by a.id
                """, new MapSqlParameterSource().addValue("epochId", epochId).addValue("asOf", java.sql.Timestamp.from(asOf))
                .addValue("membershipEdges", MEMBERSHIP_EDGES), (rs, n) -> new Agent(rs.getObject(1, UUID.class),
                rs.getString(2), rs.getString(3), rs.getString(4)));
        Map<UUID, List<Edge>> graph = currentRelationshipGraph(epochId, asOf);
        List<UUID> derived = new ArrayList<>();
        Map<UUID, Set<UUID>> current = new HashMap<>();
        for (Agent root : roots) {
            String stableKey = sha256(tenant.getId() + "|" + root.provider() + "|" + root.providerResourceId());
            UUID systemId = jdbc.queryForObject("""
                    insert into ai_grid_systems (id,tenant_id,stable_key,name,root_artifact_id,status,retired_at)
                    values (:id,:tenantId,:key,:name,:root,'ACTIVE',null)
                    on conflict (tenant_id,stable_key) do update set name=excluded.name,root_artifact_id=excluded.root_artifact_id,
                        status='ACTIVE',retired_at=null,updated_at=now() returning id
                    """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                    .addValue("key", stableKey).addValue("name", root.name()).addValue("root", root.id()), UUID.class);
            derived.add(systemId);
            List<UUID> members = applyOverrides(systemId, boundedMembers(root.id(), graph));
            current.put(systemId, Set.copyOf(members));
            createRevisionIfChanged(tenant, triggerRunId, epochId, systemId, members, "DETERMINISTIC",
                    "Authoritative complete-scope epoch " + epochId, null);
        }
        recordDerivedLineage(tenant, triggerRunId, epochId, previous, current);
        retireSystemsAbsentFromEpoch(tenant, triggerRunId, epochId, derived);
    }

    /** Creates a user-reviewed revision. Findings are deliberately not copied to the new revision. */
    public int reviseMembership(Tenant tenant, UUID systemId, UUID artifactId, String decision,
                                String actor, String reason, String lineageType, List<UUID> relatedSystems) {
        if (!Set.of("ACCEPT", "REJECT").contains(decision)) throw new IllegalArgumentException("Invalid membership decision");
        CurrentRevision current = currentRevision(systemId);
        if (current == null) throw new IllegalArgumentException("AI system has no current revision");
        LinkedHashSet<UUID> members = new LinkedHashSet<>(current.members());
        if ("ACCEPT".equals(decision)) members.add(artifactId); else members.remove(artifactId);
        jdbc.update("""
                insert into ai_grid_system_membership_overrides
                    (tenant_id,system_id,artifact_id,decision,reason,actor)
                values (:tenantId,:systemId,:artifactId,:decision,:reason,:actor)
                on conflict (tenant_id,system_id,artifact_id) do update set decision=excluded.decision,
                    reason=excluded.reason,actor=excluded.actor,decided_at=now()
                """, new MapSqlParameterSource().addValue("tenantId", tenant.getId()).addValue("systemId", systemId)
                .addValue("artifactId", artifactId).addValue("decision", decision).addValue("reason", reason)
                .addValue("actor", actor));
        int revision = createRevisionIfChanged(tenant, current.runId(), current.epochId(), systemId,
                members.stream().toList(), "USER_REVIEW",
                reason, new MembershipDecision(artifactId, decision, actor));
        UUID resultingRevisionId = jdbc.queryForObject("select id from ai_grid_system_revisions where system_id=:id and revision=:revision",
                Map.of("id", systemId, "revision", revision), UUID.class);
        jdbc.update("""
                insert into ai_grid_system_membership_decisions
                    (id,tenant_id,system_id,resulting_revision_id,artifact_id,decision,reason,actor)
                values (:id,:tenantId,:systemId,:revisionId,:artifactId,:decision,:reason,:actor)
                """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                .addValue("systemId", systemId).addValue("revisionId", resultingRevisionId)
                .addValue("artifactId", artifactId).addValue("decision", decision)
                .addValue("reason", reason).addValue("actor", actor));
        if (lineageType != null && !lineageType.isBlank()) {
            List<UUID> related = relatedSystems == null ? List.of() : relatedSystems;
            switch (lineageType) {
                case "SPLIT" -> recordLineage(tenant, null, lineageType, List.of(systemId), related, actor, reason);
                case "MERGED", "SUCCESSOR" -> recordLineage(tenant, null, lineageType, related, List.of(systemId), actor, reason);
                case "RETIRED" -> recordLineage(tenant, null, lineageType, List.of(systemId), List.of(), actor, reason);
                default -> throw new IllegalArgumentException("Invalid system lineage event");
            }
        }
        return revision;
    }

    public UUID recordLineage(Tenant tenant, UUID runId, String eventType, List<UUID> predecessors,
                              List<UUID> successors, String actor, String rationale) {
        if (!Set.of("SPLIT", "MERGED", "RETIRED", "SUCCESSOR").contains(eventType))
            throw new IllegalArgumentException("Invalid system lineage event");
        if (predecessors == null || predecessors.isEmpty())
            throw new IllegalArgumentException("A lineage event requires a predecessor");
        if (!"RETIRED".equals(eventType) && (successors == null || successors.isEmpty()))
            throw new IllegalArgumentException("A non-retirement lineage event requires a successor");
        if ("SPLIT".equals(eventType) && (predecessors.size() != 1 || successors.size() < 2))
            throw new IllegalArgumentException("A split requires one predecessor and at least two successors");
        if ("MERGED".equals(eventType) && (predecessors.size() < 2 || successors.size() != 1))
            throw new IllegalArgumentException("A merge requires at least two predecessors and one successor");
        if ("SUCCESSOR".equals(eventType) && (predecessors.size() != 1 || successors.size() != 1))
            throw new IllegalArgumentException("A successor event requires one predecessor and one successor");
        Set<UUID> participants = new HashSet<>(predecessors);
        if (successors != null) participants.addAll(successors);
        Integer existing = jdbc.queryForObject("select count(*) from ai_grid_systems where id in (:ids)",
                Map.of("ids", participants), Integer.class);
        if (existing == null || existing != participants.size()) throw new IllegalArgumentException("Unknown lineage participant");
        UUID eventId = UUID.randomUUID();
        jdbc.update("""
                insert into ai_grid_system_lineage_events
                    (id, tenant_id, event_type, run_id, rationale, evidence_json, actor)
                values (:id, :tenantId, :type, :runId, :rationale, cast(:evidence as jsonb), :actor)
                """, new MapSqlParameterSource().addValue("id", eventId).addValue("tenantId", tenant.getId())
                .addValue("type", eventType).addValue("runId", runId).addValue("rationale", rationale)
                .addValue("actor", actor).addValue("evidence", json(Map.of("noAutomaticFindingTransfer", true))));
        addParticipants(tenant, eventId, predecessors, "PREDECESSOR");
        addParticipants(tenant, eventId, successors == null ? List.of() : successors, "SUCCESSOR");
        if ("RETIRED".equals(eventType)) jdbc.update(
                "update ai_grid_systems set status='RETIRED',retired_at=now(),updated_at=now() where id in (:ids)",
                Map.of("ids", predecessors));
        return eventId;
    }

    private Map<UUID, List<Edge>> relationshipGraph(UUID runId) {
        Map<UUID, List<Edge>> graph = new HashMap<>();
        jdbc.query("""
                select source_artifact_id, target_artifact_id, relationship_type
                  from ai_grid_relationship_snapshots
                 where run_id = :runId and relationship_type in (:types)
                   and valid_from<=(select max(observed_at) from ai_grid_snapshot_manifests where run_id=:runId)
                   and (valid_until is null or valid_until>=(select max(observed_at) from ai_grid_snapshot_manifests where run_id=:runId))
                 order by source_artifact_id, relationship_type, target_artifact_id
                """, new MapSqlParameterSource().addValue("runId", runId).addValue("types", MEMBERSHIP_EDGES), rs -> {
            UUID source = rs.getObject("source_artifact_id", UUID.class);
            graph.computeIfAbsent(source, ignored -> new ArrayList<>()).add(new Edge(
                    rs.getObject("target_artifact_id", UUID.class), rs.getString("relationship_type")));
        });
        return graph;
    }

    private Map<UUID, List<Edge>> currentRelationshipGraph(UUID epochId, Instant asOf) {
        Map<UUID, List<Edge>> graph = new HashMap<>();
        jdbc.query("""
                select rel.source_artifact_id,rel.target_artifact_id,rel.relationship_type
                  from ai_grid_relationship_snapshots rel
                  join ai_grid_current_coverage_artifacts src on src.artifact_id=rel.source_artifact_id
                       and src.source_run_id=rel.run_id and src.epoch_id=:epochId
                  join ai_grid_current_coverage_artifacts dst on dst.artifact_id=rel.target_artifact_id
                       and dst.epoch_id=:epochId
                 where rel.relationship_type in (:types) and rel.valid_from<=:asOf
                   and (rel.valid_until is null or rel.valid_until>=:asOf)
                 order by rel.source_artifact_id,rel.relationship_type,rel.target_artifact_id
                """, new MapSqlParameterSource().addValue("epochId", epochId).addValue("types", MEMBERSHIP_EDGES)
                .addValue("asOf", java.sql.Timestamp.from(asOf)), rs -> {
            graph.computeIfAbsent(rs.getObject(1, UUID.class), ignored -> new ArrayList<>()).add(
                    new Edge(rs.getObject(2, UUID.class), rs.getString(3)));
        });
        return graph;
    }

    private List<UUID> boundedMembers(UUID root, Map<UUID, List<Edge>> graph) {
        Set<UUID> visited = new HashSet<>();
        ArrayDeque<NodeDepth> queue = new ArrayDeque<>();
        visited.add(root);
        queue.add(new NodeDepth(root, 0));
        while (!queue.isEmpty()) {
            NodeDepth current = queue.removeFirst();
            if (current.depth() >= MAX_DEPTH) continue;
            List<Edge> edges = graph.getOrDefault(current.id(), List.of()).stream()
                    .sorted(Comparator.comparing(Edge::type).thenComparing(e -> e.target().toString()))
                    .limit(MAX_FAN_OUT).toList();
            for (Edge edge : edges) if (visited.add(edge.target())) queue.addLast(new NodeDepth(edge.target(), current.depth() + 1));
        }
        return visited.stream().sorted(Comparator.comparing(UUID::toString)).toList();
    }

    private int createRevisionIfChanged(Tenant tenant, UUID runId, UUID coverageEpochId, UUID systemId, List<UUID> rawMembers,
                                        String source, String rationale, MembershipDecision decision) {
        List<UUID> members = rawMembers.stream().distinct().sorted(Comparator.comparing(UUID::toString)).toList();
        String hash = sha256(String.join("|", members.stream().map(UUID::toString).toList()));
        List<Integer> same = jdbc.query("""
                select r.revision from ai_grid_systems s join ai_grid_system_revisions r
                  on r.system_id=s.id and r.revision=s.current_revision
                 where s.id=:id and r.membership_hash=:hash
                """,
                Map.of("id", systemId, "hash", hash), (rs, n) -> rs.getInt(1));
        if (!same.isEmpty() && decision == null) return same.get(0);
        Integer revision = jdbc.queryForObject("select coalesce(max(revision),0)+1 from ai_grid_system_revisions where system_id=:id",
                Map.of("id", systemId), Integer.class);
        Instant now = Instant.now();
        jdbc.update("""
                update ai_grid_system_memberships set valid_until=:now where valid_until is null
                 and system_revision_id in (select id from ai_grid_system_revisions
                                              where system_id=:id and valid_until is null)
                """, Map.of("now", java.sql.Timestamp.from(now), "id", systemId));
        jdbc.update("update ai_grid_system_revisions set valid_until=:now where system_id=:id and valid_until is null",
                Map.of("now", java.sql.Timestamp.from(now), "id", systemId));
        UUID revisionId = UUID.randomUUID();
        jdbc.update("""
                insert into ai_grid_system_revisions
                    (id, tenant_id, system_id, revision, membership_hash, source, rationale, run_id, coverage_epoch_id, valid_from)
                values (:id,:tenantId,:systemId,:revision,:hash,:source,:rationale,:runId,:epochId,:validFrom)
                """, new MapSqlParameterSource().addValue("id", revisionId).addValue("tenantId", tenant.getId())
                .addValue("systemId", systemId).addValue("revision", revision).addValue("hash", hash)
                .addValue("source", source).addValue("rationale", rationale).addValue("runId", runId)
                .addValue("epochId", coverageEpochId)
                .addValue("validFrom", java.sql.Timestamp.from(now)));
        Map<UUID, String> overrides = membershipOverrides(systemId);
        for (UUID member : members) {
            boolean reviewed = "ACCEPT".equals(overrides.get(member));
            jdbc.update("""
                    insert into ai_grid_system_memberships
                        (id,tenant_id,system_revision_id,artifact_id,membership_state,confidence_method,
                         confidence_method_version,confidence,evidence_json,valid_from,decided_by,decided_at)
                    values (:id,:tenantId,:revisionId,:artifactId,'ACCEPTED',:method,'1.0.0',:confidence,
                            cast(:evidence as jsonb),:validFrom,:actor,:decidedAt)
                    """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                    .addValue("revisionId", revisionId).addValue("artifactId", member)
                    .addValue("method", reviewed ? "USER_CONFIRMED" : "PROVIDER_RELATIONSHIP")
                    .addValue("confidence", reviewed ? 1.0 : 0.95).addValue("validFrom", java.sql.Timestamp.from(now))
                    .addValue("actor", reviewed ? decision.actor() : null)
                    .addValue("decidedAt", reviewed ? java.sql.Timestamp.from(now) : null)
                    .addValue("evidence", json(Map.of("runId", runId == null ? "USER_REVISION" : runId.toString(),
                            "boundedDepth", MAX_DEPTH, "boundedFanOut", MAX_FAN_OUT))));
        }
        jdbc.update("update ai_grid_systems set current_revision=:revision,status='ACTIVE',retired_at=null,updated_at=now() where id=:id",
                Map.of("revision", revision, "id", systemId));
        return revision;
    }

    private List<UUID> applyOverrides(UUID systemId, List<UUID> derived) {
        LinkedHashSet<UUID> result = new LinkedHashSet<>(derived);
        membershipOverrides(systemId).forEach((artifact, decision) -> {
            if ("ACCEPT".equals(decision)) result.add(artifact); else result.remove(artifact);
        });
        return result.stream().sorted(Comparator.comparing(UUID::toString)).toList();
    }

    private Map<UUID, String> membershipOverrides(UUID systemId) {
        Map<UUID, String> result = new HashMap<>();
        jdbc.query("select artifact_id,decision from ai_grid_system_membership_overrides where system_id=:id",
                Map.of("id", systemId), rs -> {
            result.put(rs.getObject(1, UUID.class), rs.getString(2));
        });
        return result;
    }

    private Instant currentEpochAsOf(UUID epochId) {
        Instant value = jdbc.query("select materialized_at from ai_grid_current_coverage_state where epoch_id=:id",
                Map.of("id", epochId), rs -> rs.next() && rs.getTimestamp(1) != null ? rs.getTimestamp(1).toInstant() : null);
        if (value == null) throw new IllegalArgumentException("Coverage epoch has no artifacts");
        return value;
    }

    private void retireSystemsAbsentFromEpoch(Tenant tenant, UUID runId, UUID epochId, List<UUID> active) {
        List<UUID> retired = jdbc.query("""
                update ai_grid_systems set status='RETIRED',retired_at=now(),updated_at=now()
                 where status='ACTIVE' and id not in (:active) returning id
                """, new MapSqlParameterSource().addValue("active", active.isEmpty() ? List.of(new UUID(0, 0)) : active),
                (rs, n) -> rs.getObject(1, UUID.class));
        for (UUID id : retired) recordLineage(tenant, runId, "RETIRED", List.of(id), List.of(),
                "ai-grid-system-derivation", "Root absent from authoritative complete-scope epoch " + epochId);
    }

    private Map<UUID, Set<UUID>> activeSystemMembers() {
        Map<UUID, Set<UUID>> result = new HashMap<>();
        jdbc.query("""
                select s.id,m.artifact_id from ai_grid_systems s join ai_grid_system_revisions r
                  on r.system_id=s.id and r.revision=s.current_revision
                join ai_grid_system_memberships m on m.system_revision_id=r.id where s.status='ACTIVE'
                """, rs -> {
            result.computeIfAbsent(rs.getObject(1, UUID.class), ignored -> new HashSet<>())
                    .add(rs.getObject(2, UUID.class));
        });
        return result;
    }

    private void recordDerivedLineage(Tenant tenant, UUID runId, UUID epochId,
                                      Map<UUID, Set<UUID>> previous, Map<UUID, Set<UUID>> current) {
        Map<UUID, List<UUID>> oldToNew = new HashMap<>();
        Map<UUID, List<UUID>> newToOld = new HashMap<>();
        previous.forEach((oldId, oldMembers) -> current.forEach((newId, newMembers) -> {
            if (!oldId.equals(newId) && oldMembers.stream().anyMatch(newMembers::contains)) {
                oldToNew.computeIfAbsent(oldId, ignored -> new ArrayList<>()).add(newId);
                newToOld.computeIfAbsent(newId, ignored -> new ArrayList<>()).add(oldId);
            }
        }));
        oldToNew.forEach((oldId, successors) -> {
            if (successors.size() > 1) recordLineage(tenant, runId, "SPLIT", List.of(oldId), successors,
                    "ai-grid-system-derivation", "Membership split in authoritative epoch " + epochId);
            else if (successors.size() == 1 && newToOld.getOrDefault(successors.get(0), List.of()).size() == 1)
                recordLineage(tenant, runId, "SUCCESSOR", List.of(oldId), successors,
                        "ai-grid-system-derivation", "Root successor in authoritative epoch " + epochId);
        });
        newToOld.forEach((newId, predecessors) -> {
            if (predecessors.size() > 1) recordLineage(tenant, runId, "MERGED", predecessors, List.of(newId),
                    "ai-grid-system-derivation", "Membership merge in authoritative epoch " + epochId);
        });
    }

    private void retireInactiveRoots(Tenant tenant, UUID runId) {
        List<UUID> retired = jdbc.query("""
                update ai_grid_systems s set status='RETIRED', retired_at=now(), updated_at=now()
                 where s.status='ACTIVE' and s.root_artifact_id is not null
                   and exists (select 1 from ai_security_artifacts a where a.id=s.root_artifact_id and a.active=false)
                returning s.id
                """, (rs, n) -> rs.getObject(1, UUID.class));
        for (UUID id : retired) recordLineage(tenant, runId, "RETIRED", List.of(id), List.of(),
                "ai-grid-system-derivation", "Root artifact is inactive after complete discovery");
    }

    private void retireRunRootsNoLongerSystems(Tenant tenant, UUID runId, List<UUID> derivedSystems) {
        MapSqlParameterSource parameters = new MapSqlParameterSource().addValue("runId", runId)
                .addValue("derived", derivedSystems.isEmpty() ? List.of(new UUID(0, 0)) : derivedSystems);
        List<UUID> retired = jdbc.query("""
                update ai_grid_systems s set status='RETIRED',retired_at=now(),updated_at=now()
                 where s.status='ACTIVE' and s.id not in (:derived)
                   and exists (select 1 from ai_security_artifact_sources src
                        where src.run_id=:runId and src.artifact_id=s.root_artifact_id)
                returning s.id
                """, parameters, (rs, n) -> rs.getObject(1, UUID.class));
        for (UUID id : retired) recordLineage(tenant, runId, "RETIRED", List.of(id), List.of(),
                "ai-grid-system-derivation", "The run-scoped graph now places the root inside another AI system");
    }

    private CurrentRevision currentRevision(UUID systemId) {
        List<CurrentRevision> rows = jdbc.query("""
                select r.id, r.revision, r.run_id, r.coverage_epoch_id from ai_grid_systems s join ai_grid_system_revisions r
                  on r.system_id=s.id and r.revision=s.current_revision where s.id=:id
                """, Map.of("id", systemId), (rs, n) -> new CurrentRevision(rs.getObject(1, UUID.class),
                rs.getInt(2), rs.getObject(3, UUID.class), rs.getObject(4, UUID.class), List.of()));
        if (rows.isEmpty()) return null;
        CurrentRevision base = rows.get(0);
        List<UUID> members = jdbc.query("select artifact_id from ai_grid_system_memberships where system_revision_id=:id order by artifact_id",
                Map.of("id", base.id()), (rs, n) -> rs.getObject(1, UUID.class));
        return new CurrentRevision(base.id(), base.revision(), base.runId(), base.epochId(), members);
    }

    private void addParticipants(Tenant tenant, UUID eventId, List<UUID> systems, String role) {
        for (UUID systemId : systems.stream().distinct().toList()) jdbc.update("""
                insert into ai_grid_system_lineage_participants
                    (id,tenant_id,event_id,system_id,system_revision_id,participant_role)
                select :id,:tenantId,:eventId,s.id,r.id,:role from ai_grid_systems s
                left join ai_grid_system_revisions r on r.system_id=s.id and r.revision=s.current_revision
                where s.id=:systemId
                """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                .addValue("eventId", eventId).addValue("systemId", systemId).addValue("role", role));
    }

    private String json(Object value) {
        try { return objectMapper.writeValueAsString(value); }
        catch (Exception e) { throw new IllegalArgumentException("Unable to serialize system evidence", e); }
    }
    private String sha256(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (Exception e) { throw new IllegalStateException("Unable to hash system identity", e); }
    }
    private record Agent(UUID id, String provider, String providerResourceId, String name) {}
    private record Edge(UUID target, String type) {}
    private record NodeDepth(UUID id, int depth) {}
    private record CurrentRevision(UUID id, int revision, UUID runId, UUID epochId, List<UUID> members) {}
    private record MembershipDecision(UUID artifactId, String decision, String actor) {}
}
