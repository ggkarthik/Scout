package com.prototype.vulnwatch.aisecurity.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
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

/** Shared virtual relationship projection for per-execution and aggregate runtime views. */
@Service
public class AiAgentExecutionRelationshipProjectionService {
    static final int MAX_GROUPS = 50;
    static final int MAX_PARTICIPANT_EDGES = 200;

    private final NamedParameterJdbcTemplate jdbc;

    public AiAgentExecutionRelationshipProjectionService(NamedParameterJdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public List<ExecutionRelationship> relationships(UUID tenantId, UUID executionId) {
        return jdbc.query("""
                select relationship_type,artifact_id,artifact_name,participant_role from (
                    select 'EXECUTED_AS'::text relationship_type,x.agent_artifact_id artifact_id,a.name artifact_name,null::text participant_role
                      from ai_agent_executions x join ai_security_artifacts a on a.id=x.agent_artifact_id
                     where x.id=:executionId and x.tenant_id=:tenantId
                    union all
                    select 'EXECUTED_AS',x.agent_version_artifact_id,a.name,null::text
                      from ai_agent_executions x join ai_security_artifacts a on a.id=x.agent_version_artifact_id
                     where x.id=:executionId and x.tenant_id=:tenantId
                    union all
                    select 'PARTICIPATED_IN',p.artifact_id,a.name,p.participant_role
                      from ai_agent_execution_participants p join ai_security_artifacts a on a.id=p.artifact_id
                     where p.execution_id=:executionId and p.tenant_id=:tenantId
                ) virtual_edges order by relationship_type,participant_role,artifact_id
                """, new MapSqlParameterSource().addValue("executionId", executionId).addValue("tenantId", tenantId),
                (rs, row) -> new ExecutionRelationship(executionId, rs.getString("relationship_type"),
                        rs.getObject("artifact_id", UUID.class), rs.getString("artifact_name"), rs.getString("participant_role")));
    }

    public RuntimeOverlay aggregate(UUID tenantId, UUID rootArtifactId, Instant from, Instant to) {
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("tenantId", tenantId).addValue("rootArtifactId", rootArtifactId)
                .addValue("from", Timestamp.from(from)).addValue("to", Timestamp.from(to))
                .addValue("groupLimit", MAX_GROUPS + 1);
        List<GroupRow> rows = jdbc.query("""
                with matching_executions as (
                    select distinct x.*
                      from ai_agent_executions x
                      left join ai_agent_execution_participants root_participant
                        on root_participant.execution_id=x.id and root_participant.tenant_id=x.tenant_id
                       and root_participant.artifact_id=:rootArtifactId
                     where x.tenant_id=:tenantId and x.evidence_time>=:from and x.evidence_time<:to
                       and (x.agent_artifact_id=:rootArtifactId or x.agent_version_artifact_id=:rootArtifactId
                            or root_participant.artifact_id is not null)
                )
                select provider,source,agent_artifact_id,agent_version_artifact_id,
                       count(*) execution_count,
                       count(*) filter (where upper(status) in ('COMPLETED','SUCCEEDED','SUCCESS')) success_count,
                       count(*) filter (where upper(status) in ('FAILED','FAILURE','ERROR')) failure_count,
                       count(*) filter (where upper(status) not in ('COMPLETED','SUCCEEDED','SUCCESS','FAILED','FAILURE','ERROR')) unknown_count,
                       count(*) filter (where correlation_status='RESOLVED') resolved_count,
                       count(*) filter (where correlation_status='UNRESOLVED') unresolved_count,
                       count(*) filter (where correlation_status='NOT_APPLICABLE') not_applicable_count,
                       min(evidence_time) first_evidence_time,max(evidence_time) last_evidence_time
                  from matching_executions
                 group by provider,source,agent_artifact_id,agent_version_artifact_id
                 order by last_evidence_time desc,provider,source,agent_artifact_id,agent_version_artifact_id
                 limit :groupLimit
                """, params, (rs, row) -> new GroupRow(
                rs.getString("provider"), rs.getString("source"), rs.getObject("agent_artifact_id", UUID.class),
                rs.getObject("agent_version_artifact_id", UUID.class), rs.getLong("execution_count"),
                rs.getLong("success_count"), rs.getLong("failure_count"), rs.getLong("unknown_count"),
                rs.getLong("resolved_count"), rs.getLong("unresolved_count"), rs.getLong("not_applicable_count"),
                rs.getTimestamp("first_evidence_time").toInstant(), rs.getTimestamp("last_evidence_time").toInstant()));

        boolean groupsTruncated = rows.size() > MAX_GROUPS;
        List<GroupRow> selected = rows.stream().limit(MAX_GROUPS).toList();
        Map<GroupKey, RuntimeGroup> groupsByKey = new LinkedHashMap<>();
        selected.forEach(row -> {
            GroupKey key = new GroupKey(row.provider(), row.source(), row.agentArtifactId(), row.agentVersionArtifactId());
            groupsByKey.put(key, new RuntimeGroup(groupId(key), row.provider(), row.source(), row.agentArtifactId(),
                    row.agentVersionArtifactId(), row.executionCount(), row.successCount(), row.failureCount(),
                    row.unknownCount(), row.resolvedCount(), row.unresolvedCount(), row.notApplicableCount(),
                    row.firstEvidenceTime(), row.lastEvidenceTime()));
        });

        List<RuntimeEdge> edges = new ArrayList<>();
        for (RuntimeGroup group : groupsByKey.values()) {
            if (group.agentArtifactId() != null) edges.add(RuntimeEdge.executedAs(group.id(), group.agentArtifactId(), group.executionCount(),
                    group.firstEvidenceTime(), group.lastEvidenceTime()));
            if (group.agentVersionArtifactId() != null) edges.add(RuntimeEdge.executedAs(group.id(), group.agentVersionArtifactId(), group.executionCount(),
                    group.firstEvidenceTime(), group.lastEvidenceTime()));
        }

        boolean participantsTruncated = false;
        if (!groupsByKey.isEmpty()) {
            List<String> groupKeys = groupsByKey.keySet().stream().map(AiAgentExecutionRelationshipProjectionService::sqlGroupKey).toList();
            List<ParticipantRow> participants = jdbc.query("""
                    with matching_executions as (
                        select distinct x.*
                          from ai_agent_executions x
                          left join ai_agent_execution_participants root_participant
                            on root_participant.execution_id=x.id and root_participant.tenant_id=x.tenant_id
                           and root_participant.artifact_id=:rootArtifactId
                         where x.tenant_id=:tenantId and x.evidence_time>=:from and x.evidence_time<:to
                           and (x.agent_artifact_id=:rootArtifactId or x.agent_version_artifact_id=:rootArtifactId
                                or root_participant.artifact_id is not null)
                    )
                    select x.provider,x.source,x.agent_artifact_id,x.agent_version_artifact_id,
                           p.artifact_id,p.participant_role,count(distinct x.id) execution_count,
                           min(p.evidence_time) first_evidence_time,max(p.evidence_time) last_evidence_time
                      from matching_executions x
                      join ai_agent_execution_participants p on p.execution_id=x.id and p.tenant_id=x.tenant_id
                     where concat_ws('|',x.provider,x.source,coalesce(x.agent_artifact_id::text,''),
                                      coalesce(x.agent_version_artifact_id::text,'')) in (:groupKeys)
                     group by x.provider,x.source,x.agent_artifact_id,x.agent_version_artifact_id,p.artifact_id,p.participant_role
                     order by last_evidence_time desc,p.artifact_id,p.participant_role
                     limit :participantLimit
                    """, params.addValue("groupKeys", groupKeys).addValue("participantLimit", MAX_PARTICIPANT_EDGES + 1), (rs, row) -> new ParticipantRow(
                    new GroupKey(rs.getString("provider"), rs.getString("source"), rs.getObject("agent_artifact_id", UUID.class),
                            rs.getObject("agent_version_artifact_id", UUID.class)), rs.getObject("artifact_id", UUID.class),
                    rs.getString("participant_role"), rs.getLong("execution_count"),
                    rs.getTimestamp("first_evidence_time").toInstant(), rs.getTimestamp("last_evidence_time").toInstant()));
            List<ParticipantRow> selectedParticipants = participants.stream().limit(MAX_PARTICIPANT_EDGES).toList();
            participantsTruncated = participants.size() > MAX_PARTICIPANT_EDGES;
            selectedParticipants.forEach(row -> edges.add(RuntimeEdge.participatedIn(
                    groupsByKey.get(row.groupKey()).id(), row.artifactId(), row.participantRole(), row.executionCount(),
                    row.firstEvidenceTime(), row.lastEvidenceTime())));
        }

        long executionCount = selected.stream().mapToLong(GroupRow::executionCount).sum();
        long resolvedCount = selected.stream().mapToLong(GroupRow::resolvedCount).sum();
        long unresolvedCount = selected.stream().mapToLong(GroupRow::unresolvedCount).sum();
        long notApplicableCount = selected.stream().mapToLong(GroupRow::notApplicableCount).sum();
        return new RuntimeOverlay("AVAILABLE", null, from, to, executionCount, resolvedCount, unresolvedCount,
                notApplicableCount, new ArrayList<>(groupsByKey.values()), edges, groupsTruncated || participantsTruncated);
    }

    public static RuntimeOverlay unavailable(Instant from, Instant to) {
        return new RuntimeOverlay("UNAVAILABLE", "RUNTIME_OVERLAY_QUERY_FAILED", from, to, 0, 0, 0, 0,
                List.of(), List.of(), false);
    }

    public static Set<UUID> referencedArtifactIds(RuntimeOverlay overlay) {
        Set<UUID> ids = new LinkedHashSet<>();
        overlay.groups().forEach(group -> {
            if (group.agentArtifactId() != null) ids.add(group.agentArtifactId());
            if (group.agentVersionArtifactId() != null) ids.add(group.agentVersionArtifactId());
        });
        overlay.edges().forEach(edge -> { if (edge.artifactId() != null) ids.add(edge.artifactId()); });
        return ids;
    }

    private static String groupId(GroupKey key) {
        String material = key.provider() + '|' + key.source() + '|' + key.agentArtifactId() + '|'
                + key.agentVersionArtifactId();
        try {
            return "runtime-aggregate:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(material.getBytes(StandardCharsets.UTF_8))).substring(0, 32);
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException(error);
        }
    }

    private static String sqlGroupKey(GroupKey key) {
        return key.provider() + '|' + key.source() + '|' + (key.agentArtifactId() == null ? "" : key.agentArtifactId())
                + '|' + (key.agentVersionArtifactId() == null ? "" : key.agentVersionArtifactId());
    }

    private record GroupKey(String provider, String source, UUID agentArtifactId, UUID agentVersionArtifactId) { }
    private record GroupRow(String provider, String source, UUID agentArtifactId, UUID agentVersionArtifactId,
                            long executionCount, long successCount, long failureCount, long unknownCount,
                            long resolvedCount, long unresolvedCount, long notApplicableCount,
                            Instant firstEvidenceTime, Instant lastEvidenceTime) { }
    private record ParticipantRow(GroupKey groupKey, UUID artifactId, String participantRole, long executionCount,
                                  Instant firstEvidenceTime, Instant lastEvidenceTime) { }

    public record ExecutionRelationship(UUID executionId, String relationshipType, UUID artifactId,
                                        String artifactName, String participantRole) { }
    public record RuntimeGroup(String id, String provider, String source, UUID agentArtifactId,
                               UUID agentVersionArtifactId, long executionCount, long successCount,
                               long failureCount, long unknownCount, long resolvedCount, long unresolvedCount,
                               long notApplicableCount, Instant firstEvidenceTime, Instant lastEvidenceTime) { }
    public record RuntimeEdge(String id, String relationshipType, String runtimeGroupId, UUID artifactId,
                              String participantRole, long executionCount, Instant firstEvidenceTime,
                              Instant lastEvidenceTime) {
        static RuntimeEdge executedAs(String groupId, UUID artifactId, long count, Instant first, Instant last) {
            return new RuntimeEdge(edgeId("EXECUTED_AS", groupId, artifactId, null), "EXECUTED_AS", groupId,
                    artifactId, null, count, first, last);
        }
        static RuntimeEdge participatedIn(String groupId, UUID artifactId, String role, long count, Instant first, Instant last) {
            return new RuntimeEdge(edgeId("PARTICIPATED_IN", groupId, artifactId, role), "PARTICIPATED_IN", groupId,
                    artifactId, role, count, first, last);
        }
        private static String edgeId(String type, String groupId, UUID artifactId, String role) {
            return "runtime-edge:" + type.toLowerCase() + ':' + groupId.substring("runtime-aggregate:".length())
                    + ':' + artifactId + (role == null ? "" : ':' + role.toLowerCase());
        }
    }
    public record RuntimeOverlay(String status, String diagnostic, Instant windowStart, Instant windowEnd,
                                 long executionCount, long resolvedCount, long unresolvedCount,
                                 long notApplicableCount, List<RuntimeGroup> groups, List<RuntimeEdge> edges,
                                 boolean truncated) { }
}
