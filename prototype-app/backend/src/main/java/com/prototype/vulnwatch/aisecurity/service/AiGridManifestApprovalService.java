package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/** Tenant control plane for immutable agent-version baselines and approved executable components. */
@Service
public class AiGridManifestApprovalService {
    private final NamedParameterJdbcTemplate jdbc;
    private final TenantSchemaExecutionService tenantExecution;
    private final ObjectMapper mapper;
    private final AuditEventService audit;

    public AiGridManifestApprovalService(NamedParameterJdbcTemplate jdbc, TenantSchemaExecutionService tenantExecution,
                                         ObjectMapper mapper, AuditEventService audit) {
        this.jdbc = jdbc; this.tenantExecution = tenantExecution; this.mapper = mapper; this.audit = audit;
    }

    public List<ApprovedManifest> manifests(Tenant tenant) {
        return tenantExecution.run(tenant, () -> jdbc.query("""
                select id,agent_artifact_id,version_artifact_id,manifest_digest,components_json::text,
                       approval_status,approved_by,approved_at,revoked_by,revoked_at,updated_at
                  from ai_grid_approved_agent_manifests order by updated_at desc
                """, (rs, row) -> new ApprovedManifest(rs.getObject(1, UUID.class), rs.getObject(2, UUID.class),
                rs.getObject(3, UUID.class), rs.getString(4), rs.getString(5), rs.getString(6), rs.getString(7),
                instant(rs, 8), rs.getString(9), instant(rs, 10), rs.getTimestamp(11).toInstant())));
    }

    public ApprovedManifest approveManifest(Tenant tenant, UUID versionArtifactId, ManifestCommand command, String actor) {
        if (command == null || command.agentArtifactId() == null || command.components() == null || command.components().isEmpty()) {
            throw bad("Agent, version, and at least one approved component are required");
        }
        for (ManifestComponent component : command.components()) {
            if (component == null || blank(component.componentType()) || component.artifactId() == null || blank(component.digest())) {
                throw bad("Approved manifest components require type, artifactId, and digest");
            }
        }
        List<ManifestComponent> components = command.components().stream()
                .sorted(Comparator.comparing(ManifestComponent::componentType)
                        .thenComparing(component -> component.artifactId().toString())
                        .thenComparing(ManifestComponent::digest))
                .toList();
        if (components.stream().map(ManifestComponent::artifactId).distinct().count() != components.size()) {
            throw bad("Approved manifest cannot contain the same component artifact more than once");
        }
        return tenantExecution.run(tenant, () -> {
            assertManifestArtifacts(command.agentArtifactId(), versionArtifactId);
            Integer componentCount = jdbc.queryForObject("""
                    select count(*) from ai_security_artifacts where active=true and id in (:componentIds)
                    """, Map.of("componentIds", components.stream().map(ManifestComponent::artifactId).toList()), Integer.class);
            if (componentCount == null || componentCount != components.size()) {
                throw bad("Approved manifest contains an inactive or unknown component artifact");
            }
            String json = json(components);
            String digest = sha256(json);
            UUID id = UUID.randomUUID();
            jdbc.update("""
                    insert into ai_grid_approved_agent_manifests
                        (id,tenant_id,agent_artifact_id,version_artifact_id,manifest_digest,components_json,
                         approval_status,approved_by,approved_at)
                    values (:id,:tenantId,:agentId,:versionId,:digest,cast(:components as jsonb),'APPROVED',:actor,now())
                    on conflict (tenant_id,version_artifact_id) do update set
                        agent_artifact_id=excluded.agent_artifact_id,manifest_digest=excluded.manifest_digest,
                        components_json=excluded.components_json,approval_status='APPROVED',approved_by=excluded.approved_by,
                        approved_at=now(),revoked_by=null,revoked_at=null,updated_at=now()
                    """, new MapSqlParameterSource().addValue("id", id).addValue("tenantId", tenant.getId())
                    .addValue("agentId", command.agentArtifactId()).addValue("versionId", versionArtifactId)
                    .addValue("digest", digest).addValue("components", json).addValue("actor", actor));
            audit.record("ai_grid.agent_manifest.approved", "ai_agent_version", versionArtifactId.toString(),
                    "{\"manifestDigest\":\"" + digest + "\"}");
            return manifests(tenant).stream().filter(value -> value.versionArtifactId().equals(versionArtifactId))
                    .findFirst().orElseThrow();
        });
    }

    public void revokeManifest(Tenant tenant, UUID versionArtifactId, String actor) {
        tenantExecution.run(tenant, () -> {
            int changed = jdbc.update("""
                    update ai_grid_approved_agent_manifests set approval_status='REVOKED',revoked_by=:actor,
                           revoked_at=now(),updated_at=now()
                     where tenant_id=:tenantId and version_artifact_id=:versionId and approval_status='APPROVED'
                    """, Map.of("tenantId", tenant.getId(), "versionId", versionArtifactId, "actor", actor));
            if (changed == 0) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Approved manifest not found");
            audit.record("ai_grid.agent_manifest.revoked", "ai_agent_version", versionArtifactId.toString(), "{}");
        });
    }

    public List<ComponentAllowlistEntry> allowlist(Tenant tenant) {
        return tenantExecution.run(tenant, () -> jdbc.query("""
                select id,provider,component_kind,component_digest,status,approved_by,approved_at,revoked_by,revoked_at
                  from ai_grid_component_allowlists order by provider,component_kind,component_digest
                """, (rs, row) -> new ComponentAllowlistEntry(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3),
                rs.getString(4), rs.getString(5), rs.getString(6), rs.getTimestamp(7).toInstant(), rs.getString(8), instant(rs, 9))));
    }

    public ComponentAllowlistEntry approveComponent(Tenant tenant, ComponentCommand command, String actor) {
        if (command == null || blank(command.provider()) || blank(command.componentKind()) || blank(command.componentDigest())) {
            throw bad("Provider, component kind, and component digest are required");
        }
        return tenantExecution.run(tenant, () -> {
            UUID id = UUID.randomUUID();
            jdbc.update("""
                    insert into ai_grid_component_allowlists
                        (id,tenant_id,provider,component_kind,component_digest,status,approved_by,approved_at)
                    values (:id,:tenantId,:provider,:kind,:digest,'APPROVED',:actor,now())
                    on conflict (tenant_id,provider,component_kind,component_digest) do update set
                        status='APPROVED',approved_by=excluded.approved_by,approved_at=now(),
                        revoked_by=null,revoked_at=null,updated_at=now()
                    """, new MapSqlParameterSource().addValue("id", id).addValue("tenantId", tenant.getId())
                    .addValue("provider", command.provider()).addValue("kind", command.componentKind())
                    .addValue("digest", command.componentDigest()).addValue("actor", actor));
            audit.record("ai_grid.component_allowlist.approved", "ai_component", command.componentDigest(), "{}");
            return allowlist(tenant).stream().filter(value -> value.provider().equals(command.provider())
                    && value.componentKind().equals(command.componentKind())
                    && value.componentDigest().equals(command.componentDigest())).findFirst().orElseThrow();
        });
    }

    public void revokeComponent(Tenant tenant, UUID entryId, String actor) {
        tenantExecution.run(tenant, () -> {
            int changed = jdbc.update("""
                    update ai_grid_component_allowlists set status='REVOKED',revoked_by=:actor,
                           revoked_at=now(),updated_at=now()
                     where tenant_id=:tenantId and id=:id and status='APPROVED'
                    """, Map.of("tenantId", tenant.getId(), "id", entryId, "actor", actor));
            if (changed == 0) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Approved component not found");
            audit.record("ai_grid.component_allowlist.revoked", "ai_component_allowlist", entryId.toString(), "{}");
        });
    }

    private void assertManifestArtifacts(UUID agentId, UUID versionId) {
        Integer valid = jdbc.queryForObject("""
                select count(distinct agent.id) from ai_security_artifacts agent
                  join ai_security_artifacts version on version.id=:versionId and version.tenant_id=agent.tenant_id
                  join ai_security_relationships relationship
                    on relationship.source_artifact_id=version.id and relationship.target_artifact_id=agent.id
                   and relationship.relationship_type='VERSION_OF' and relationship.active=true
                 where agent.id=:agentId and agent.artifact_type='AI_AGENT' and agent.active=true
                   and version.artifact_type='AI_AGENT_VERSION' and version.active=true
                """, Map.of("agentId", agentId, "versionId", versionId), Integer.class);
        if (valid == null || valid != 1) throw bad("Version is not an active version of the requested agent");
    }

    private String json(Object value) {
        try { return mapper.writeValueAsString(value); }
        catch (Exception exception) { throw new IllegalArgumentException("Manifest components are not serializable", exception); }
    }
    private String sha256(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (Exception exception) { throw new IllegalStateException(exception); }
    }
    private static Instant instant(java.sql.ResultSet result, int column) throws java.sql.SQLException {
        var timestamp = result.getTimestamp(column); return timestamp == null ? null : timestamp.toInstant();
    }
    private static boolean blank(String value) { return value == null || value.isBlank(); }
    private static ResponseStatusException bad(String message) { return new ResponseStatusException(HttpStatus.BAD_REQUEST, message); }

    public record ManifestComponent(String componentType, UUID artifactId, String digest) {}
    public record ManifestCommand(UUID agentArtifactId, List<ManifestComponent> components) {}
    public record ComponentCommand(String provider, String componentKind, String componentDigest) {}
    public record ApprovedManifest(UUID id, UUID agentArtifactId, UUID versionArtifactId, String manifestDigest,
                                   String componentsJson, String approvalStatus, String approvedBy, Instant approvedAt,
                                   String revokedBy, Instant revokedAt, Instant updatedAt) {}
    public record ComponentAllowlistEntry(UUID id, String provider, String componentKind, String componentDigest,
                                          String status, String approvedBy, Instant approvedAt,
                                          String revokedBy, Instant revokedAt) {}
}
