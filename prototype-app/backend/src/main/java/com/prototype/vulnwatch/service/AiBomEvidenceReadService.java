package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.AiBomCorrelationEvidenceResponse;
import com.prototype.vulnwatch.repo.AiBomDeclaredResourceRepository;
import com.prototype.vulnwatch.repo.BomComponentRepository;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AiBomEvidenceReadService {
    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final AiBomDeclaredResourceRepository resources;
    private final BomComponentRepository components;

    @Transactional(readOnly = true)
    public AiBomCorrelationEvidenceResponse read(Tenant tenant, UUID resourceId, boolean history, int page, int size) {
        resources.findById(resourceId).filter(r -> tenant.getId().equals(r.getTenantId()))
                .orElseThrow(() -> new jakarta.persistence.EntityNotFoundException("Declared AI-BOM resource not found"));
        int safeSize = Math.max(1, Math.min(size, 100));
        int safePage = Math.max(0, Math.min(page, 1000000));
        Map<String, Object> p = Map.of("tenant", tenant.getId(), "resource", resourceId,
                "status", history ? "RETIRED" : "ACTIVE", "size", safeSize, "offset", (long) safePage * safeSize);
        long pathCount = jdbc.queryForObject("select count(*) from ai_bom_correlation_paths where tenant_id=:tenant and declared_resource_id=:resource and status=:status", p, Long.class);
        long gapCount = jdbc.queryForObject("select count(*) from ai_bom_correlation_gaps where tenant_id=:tenant and declared_resource_id=:resource and resolved_at is null", p, Long.class);
        var rows = jdbc.queryForList("""
                select p.*, l.finding_id, p.component_ids::text as ids_json, p.component_refs::text as refs_json,
                    p.relationship_ids::text as edges_json, p.lifecycle_history::text as history_json,
                    (p.source_revision <> s.revision or p.bom_id is distinct from s.current_bom_id or exists (select 1 from ai_bom_correlation_gaps g where g.tenant_id=p.tenant_id
                        and g.declared_resource_id=p.declared_resource_id and g.resolved_at is null
                        and (g.component_ref is null or p.component_refs @> jsonb_build_array(g.component_ref)))) as uncertain
                from ai_bom_correlation_paths p join ai_bom_resource_vulnerability_links l on l.id=p.link_id
                join bom_sources s on s.id=p.source_id and s.tenant_id=p.tenant_id
                where p.tenant_id=:tenant and p.declared_resource_id=:resource and p.status=:status
                order by p.confirmed_at desc,p.id limit :size offset :offset
                """, p);
        Set<UUID> ids = new LinkedHashSet<>();
        rows.forEach(row -> strings(row.get("ids_json")).forEach(id -> ids.add(UUID.fromString(id))));
        Map<UUID, com.prototype.vulnwatch.domain.BomComponent> byId = new HashMap<>();
        components.findAllById(ids).forEach(c -> byId.put(c.getId(), c));
        List<AiBomCorrelationEvidenceResponse.Path> paths = rows.stream().map(row -> {
            var nodeIds = strings(row.get("ids_json"));
            var refs = strings(row.get("refs_json"));
            List<AiBomCorrelationEvidenceResponse.Component> nodes = new ArrayList<>();
            for (int i = 0; i < nodeIds.size(); i++) {
                UUID id = UUID.fromString(nodeIds.get(i));
                var c = byId.get(id);
                nodes.add(new AiBomCorrelationEvidenceResponse.Component(id, refs.get(i), c == null ? refs.get(i) : c.getName(), c == null ? null : c.getVersion()));
            }
            return new AiBomCorrelationEvidenceResponse.Path((UUID) row.get("id"), (UUID) row.get("finding_id"),
                    row.get("status").toString(), (UUID) row.get("bom_id"), ((Number) row.get("source_revision")).longValue(),
                    nodes, strings(row.get("edges_json")).stream().map(UUID::fromString).toList(),
                    (UUID) row.get("terminal_component_id"), row.get("match_method").toString(),
                    instant(row.get("confirmed_at")), instant(row.get("retired_at")), (String) row.get("retirement_reason"),
                    !history && Boolean.TRUE.equals(row.get("uncertain")), lifecycle(row.get("history_json")));
        }).toList();
        List<AiBomCorrelationEvidenceResponse.Gap> gaps = history ? List.of() : jdbc.query("""
                select * from ai_bom_correlation_gaps where tenant_id=:tenant and declared_resource_id=:resource
                and resolved_at is null order by detected_at,id limit :size offset :offset
                """, p, (rs, n) -> new AiBomCorrelationEvidenceResponse.Gap(rs.getObject("id", UUID.class),
                        rs.getObject("component_id", UUID.class), rs.getString("component_ref"), rs.getString("reason"),
                        remediation(rs.getString("reason")), rs.getLong("source_revision"), rs.getTimestamp("detected_at").toInstant()));
        String legacyPredicate = " from ai_bom_resource_vulnerability_links l where l.tenant_id=:tenant"
                + " and l.declared_resource_id=:resource and l.status=:status"
                + " and not exists (select 1 from ai_bom_correlation_paths p where p.link_id=l.id)";
        long associationCount = jdbc.queryForObject("select count(*)" + legacyPredicate, p, Long.class);
        var associations = jdbc.queryForList("select l.*, l.lifecycle_history::text as history_json" + legacyPredicate
                + " order by l.detected_at,l.id limit :size offset :offset", p).stream()
                .map(row -> new AiBomCorrelationEvidenceResponse.Association((UUID) row.get("id"),
                        (UUID) row.get("finding_id"), row.get("status").toString(), instant(row.get("confirmed_at")),
                        instant(row.get("retired_at")), (String) row.get("retirement_reason"), lifecycle(row.get("history_json")))).toList();
        return new AiBomCorrelationEvidenceResponse(paths, gaps, pathCount, history ? 0 : gapCount, safePage, safeSize, associations, associationCount);
    }
    private List<AiBomCorrelationEvidenceResponse.LifecycleEvent> lifecycle(Object value) {
        try { return mapper.readValue(value.toString(), new TypeReference<List<AiBomCorrelationEvidenceResponse.LifecycleEvent>>() { }); }
        catch (Exception e) { throw new IllegalStateException("Cannot read association history", e); }
    }
    private List<String> strings(Object value) {
        try { return mapper.readValue(value.toString(), new TypeReference<List<String>>() { }); }
        catch (Exception e) { throw new IllegalStateException("Cannot read dependency evidence", e); }
    }
    private Instant instant(Object value) { return value == null ? null : ((Timestamp) value).toInstant(); }
    static String remediation(String reason) {
        return switch (reason) {
            case "SOURCE_DOCUMENT_UNAVAILABLE" -> "Upload a valid current BOM. Existing support remains until current source assertions can be evaluated.";
            case "VERSION_MISSING" -> "Provide an exact dependency version in the component or package URL.";
            case "VERSION_CONFLICT" -> "Make the component version and package URL version agree.";
            case "VERSION_INVALID" -> "Provide a valid version for the dependency ecosystem.";
            case "IDENTITY_AMBIGUOUS" -> "Disambiguate duplicate package identities, including ecosystem and namespace.";
            case "TRAVERSAL_LIMIT_REACHED" -> "Reduce the dependency graph or ask an administrator to increase traversal limits.";
            case "RECONCILIATION_FAILED" -> "Reconciliation could not complete. Existing support is retained; the next sweep will retry.";
            case "INVENTORY_MATCH_MISSING" -> "Check that the declared software dependency has entered the asset inventory.";
            default -> "Provide a resolvable dependency reference and explicit ecosystem/package identity.";
        };
    }
}
