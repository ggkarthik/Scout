package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class AiGridSystemService {
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
                 where s.run_id = :runId and a.active = true and a.artifact_type = 'AI_AGENT'
                """, Map.of("runId", runId), (rs, n) -> new Agent(rs.getObject("id", UUID.class),
                rs.getString("provider"), rs.getString("provider_resource_id"), rs.getString("name")));
        for (Agent agent : agents) {
            List<UUID> members = new ArrayList<>();
            members.add(agent.id());
            members.addAll(jdbc.query("""
                    select target_artifact_id from ai_grid_relationship_snapshots
                     where run_id = :runId and source_artifact_id = :agentId
                       and relationship_type in ('USES_GUARDRAIL','USES_KNOWLEDGE_BASE','USES_MODEL')
                    """, Map.of("runId", runId, "agentId", agent.id()),
                    (rs, n) -> rs.getObject(1, UUID.class)));
            members = members.stream().distinct().sorted(Comparator.comparing(UUID::toString)).toList();
            String stableKey = sha256(tenant.getId() + "|" + agent.provider() + "|" + agent.providerResourceId());
            UUID systemId = jdbc.queryForObject("""
                    insert into ai_grid_systems (id, tenant_id, stable_key, name)
                    values (:id, :tenantId, :stableKey, :name)
                    on conflict (tenant_id, stable_key) do update set name = excluded.name, updated_at = now()
                    returning id
                    """, new MapSqlParameterSource().addValue("id", UUID.randomUUID())
                    .addValue("tenantId", tenant.getId()).addValue("stableKey", stableKey).addValue("name", agent.name()), UUID.class);
            String membershipHash = sha256(String.join("|", members.stream().map(UUID::toString).toList()));
            Integer existing = jdbc.queryForObject("""
                    select count(*) from ai_grid_system_revisions
                     where system_id = :systemId and membership_hash = :hash
                    """, Map.of("systemId", systemId, "hash", membershipHash), Integer.class);
            if (existing != null && existing > 0) continue;
            Integer revision = jdbc.queryForObject("""
                    select coalesce(max(revision), 0) + 1 from ai_grid_system_revisions where system_id = :systemId
                    """, Map.of("systemId", systemId), Integer.class);
            UUID revisionId = UUID.randomUUID();
            jdbc.update("""
                    insert into ai_grid_system_revisions
                        (id, tenant_id, system_id, revision, membership_hash, source, rationale)
                    values (:id, :tenantId, :systemId, :revision, :hash, 'DETERMINISTIC',
                            'Provider relationship grouping for the agent root')
                    """, new MapSqlParameterSource().addValue("id", revisionId).addValue("tenantId", tenant.getId())
                    .addValue("systemId", systemId).addValue("revision", revision).addValue("hash", membershipHash));
            for (UUID member : members) {
                jdbc.update("""
                        insert into ai_grid_system_memberships
                            (id, tenant_id, system_revision_id, artifact_id, membership_state,
                             confidence_method, confidence_method_version, confidence, evidence_json)
                        values (:id, :tenantId, :revisionId, :artifactId, 'ACCEPTED',
                                'PROVIDER_RELATIONSHIP', '1.0.0', 1.0, cast(:evidence as jsonb))
                        """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                        .addValue("revisionId", revisionId).addValue("artifactId", member)
                        .addValue("evidence", json(Map.of("runId", runId))));
            }
            jdbc.update("update ai_grid_systems set current_revision = :revision, updated_at = now() where id = :id",
                    Map.of("revision", revision, "id", systemId));
        }
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
}
