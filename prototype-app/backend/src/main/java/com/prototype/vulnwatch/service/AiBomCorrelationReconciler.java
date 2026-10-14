package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.*;
import com.prototype.vulnwatch.repo.*;
import java.util.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/** Transaction owner; invoked through a Spring proxy after tenant context is established. */
@Service
@Slf4j
public class AiBomCorrelationReconciler {
    private final AiBomDeclaredResourceRepository resources;
    private final BomComponentRepository components;
    private final BomComponentRelationshipRepository relationships;
    private final InventoryComponentRepository inventory;
    private final FindingRepository findings;
    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final boolean writesEnabled;
    private final boolean retirementEnabled;
    private final AiBomCorrelationResolver.Limits limits;

    public AiBomCorrelationReconciler(AiBomDeclaredResourceRepository resources, BomComponentRepository components,
            BomComponentRelationshipRepository relationships, InventoryComponentRepository inventory,
            FindingRepository findings, NamedParameterJdbcTemplate jdbc, ObjectMapper mapper,
            @Value("${app.ai-bom.correlation.writes-enabled:true}") boolean writesEnabled,
            @Value("${app.ai-bom.correlation.retirement-enabled:false}") boolean retirementEnabled,
            @Value("${app.ai-bom.correlation.max-depth:16}") int depth,
            @Value("${app.ai-bom.correlation.max-nodes:10000}") int nodes,
            @Value("${app.ai-bom.correlation.max-edges:20000}") int edges,
            @Value("${app.ai-bom.correlation.max-paths:2000}") int paths) {
        this.resources = resources; this.components = components; this.relationships = relationships;
        this.inventory = inventory; this.findings = findings; this.jdbc = jdbc; this.mapper = mapper;
        this.writesEnabled = writesEnabled; this.retirementEnabled = retirementEnabled;
        this.limits = new AiBomCorrelationResolver.Limits(depth, nodes, edges, paths);
    }

    private record Snapshot(UUID bom, UUID asset, long revision) { }

    /** Lock order: tenant context, source row, resource row. Uploads lock the same source first. */
    private Snapshot lock(Tenant tenant, UUID sourceId, UUID resourceId, long revision) {
        var params = Map.of("tenant", tenant.getId(), "source", sourceId, "resource", resourceId);
        List<Snapshot> snapshots = jdbc.query("""
                select current_bom_id, asset_id, revision from bom_sources
                where tenant_id=:tenant and id=:source for update
                """, params, (rs, n) -> new Snapshot(rs.getObject(1, UUID.class), rs.getObject(2, UUID.class), rs.getLong(3)));
        if (snapshots.isEmpty() || revision >= 0 && snapshots.get(0).revision() != revision) {
            log.info("AI-BOM stale computation skipped tenant={} source={} resource={}", tenant.getId(), sourceId, resourceId);
            return null;
        }
        jdbc.queryForList("select id from ai_bom_declared_resources where tenant_id=:tenant and id=:resource for update", params);
        return snapshots.get(0);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void reconcile(Tenant tenant, UUID resourceId, UUID sourceId, long capturedRevision) {
        Snapshot snapshot = lock(tenant, sourceId, resourceId, capturedRevision);
        if (snapshot == null) return;
        AiBomDeclaredResource resource = resources.findById(resourceId).orElse(null);
        if (resource == null || !tenant.getId().equals(resource.getTenantId()) || !sourceId.equals(resource.getSourceId())) return;
        AiBomCorrelationResolver.Result result;
        String documentStatus = snapshot.bom() == null ? null : jdbc.queryForObject(
                "select status from bom_ingestion_records where id=:bom and tenant_id=:tenant",
                Map.of("bom", snapshot.bom(), "tenant", tenant.getId()), String.class);
        boolean unavailable = documentStatus == null || Set.of("FAILED", "PROCESSING").contains(documentStatus);
        boolean documentWithdrawn = !unavailable && Set.of("SUPERSEDED", "DELETED").contains(documentStatus);
        boolean omitted = !unavailable && (!Objects.equals(snapshot.bom(), resource.getBomId()) || documentWithdrawn);
        if (unavailable) {
            result = new AiBomCorrelationResolver.Result(List.of(),
                    Set.of(new AiBomCorrelationResolver.Gap(null, null, "SOURCE_DOCUMENT_UNAVAILABLE")), Set.of(), false);
        } else if (omitted) {
            // Document assertions are source-scoped, even when the replacement is PARTIAL.
            result = new AiBomCorrelationResolver.Result(List.of(), Set.of(), Set.of(), true);
        } else if (snapshot.bom() == null || snapshot.asset() == null) {
            result = new AiBomCorrelationResolver.Result(List.of(),
                    Set.of(new AiBomCorrelationResolver.Gap(null, null, "IDENTITY_MISSING")), Set.of(), false);
        } else {
            List<BomComponent> document = components.findByBomIdAndActiveTrue(snapshot.bom());
            List<AiBomCorrelationResolver.Node> nodes = document.stream().filter(c -> snapshot.bom().equals(c.getBomId()))
                    .map(c -> new AiBomCorrelationResolver.Node(c.getId(), c.getBomRef(), c.getName(), c.getGroupName(),
                            ecosystem(c), c.getVersion(), c.getPurl(),
                            new BomComponentCategorizationService().entersSoftwareInventory(c.getComponentType())
                                    && c.getCategory() != BomComponentCategory.AI_MODEL
                                    && c.getCategory() != BomComponentCategory.CRYPTOGRAPHIC)).toList();
            List<AiBomCorrelationResolver.Edge> edges = relationships.findByBomId(snapshot.bom()).stream()
                    .filter(e -> snapshot.bom().equals(e.getBomId()))
                    .map(e -> new AiBomCorrelationResolver.Edge(e.getId(), e.getSourceComponentId(), e.getTargetComponentId(),
                            e.getSourceRef(), e.getTargetRef(), e.getRelationshipType())).toList();
            List<AiBomCorrelationResolver.Package> packages = inventory.findByAssetId(snapshot.asset()).stream()
                    .filter(c -> c.getTenant() != null && tenant.getId().equals(c.getTenant().getId()))
                    .map(c -> new AiBomCorrelationResolver.Package(c.getId(), c.getPackageName(), c.getPackageGroup(),
                            c.getEcosystem(), c.getVersion(), c.getPurl(), c.getComponentStatus() == InventoryComponentStatus.ACTIVE)).toList();
            result = AiBomCorrelationResolver.resolve(resource.getBomComponentId(), nodes, edges, packages, limits);
        }
        if (!writesEnabled) {
            log.info("AI-BOM writes disabled tenant={} source={} resource={} desiredPaths={} gaps={}",
                    tenant.getId(), sourceId, resourceId, result.paths().size(), result.gaps().size());
            return;
        }
        apply(tenant, resource, snapshot, result, omitted);
    }

    private String ecosystem(BomComponent c) {
        if (c.getProperties() == null) return null;
        try {
            var properties = mapper.readTree(c.getProperties());
            if (properties.isObject()) return properties.path("ecosystem").asText(null);
            for (var property : properties) {
                if (Set.of("ecosystem", "cdx:ecosystem", "noscan:ecosystem").contains(property.path("name").asText()))
                    return property.path("value").asText(null);
            }
            return null;
        } catch (Exception e) { return null; }
    }

    private Map<String, Object> params(Tenant tenant, AiBomDeclaredResource resource, Snapshot snapshot) {
        Map<String, Object> p = new HashMap<>();
        p.put("tenant", tenant.getId()); p.put("resource", resource.getId()); p.put("source", resource.getSourceId());
        p.put("bom", snapshot.bom()); p.put("revision", snapshot.revision());
        return p;
    }

    private void apply(Tenant tenant, AiBomDeclaredResource resource, Snapshot snapshot,
                       AiBomCorrelationResolver.Result result, boolean omitted) {
        Map<String, Object> p = params(tenant, resource, snapshot);
        var retiredIdsBefore = new HashSet<>(jdbc.queryForList(
                "select id from ai_bom_resource_vulnerability_links where tenant_id=:tenant and declared_resource_id=:resource and status='RETIRED'", p, UUID.class));
        long activeBefore = jdbc.queryForObject("select count(*) from ai_bom_resource_vulnerability_links where tenant_id=:tenant and declared_resource_id=:resource and status='ACTIVE'", p, Long.class);
        Set<UUID> desiredLinks = new HashSet<>();
        Set<String> desired = new HashSet<>();
        Set<UUID> terminalIds = new HashSet<>();
        result.paths().forEach(path -> terminalIds.add(path.terminal()));
        List<Finding> candidates = terminalIds.isEmpty() ? List.of() : findings.findByComponent_IdIn(terminalIds);
        for (AiBomCorrelationResolver.Path path : result.paths()) {
            for (Finding finding : candidates) {
                if (!"VULNERABILITY".equals(finding.getFindingKind()) || finding.getComponent() == null
                        || !path.terminal().equals(finding.getComponent().getId())
                        || finding.getTenant() == null || !tenant.getId().equals(finding.getTenant().getId())) continue;
                p.put("finding", finding.getId()); p.put("terminal", path.terminal()); p.put("id", UUID.randomUUID());
                UUID link = jdbc.queryForObject("""
                        insert into ai_bom_resource_vulnerability_links
                        (id,tenant_id,declared_resource_id,finding_id,via_component_id,correlation_method,status,confirmed_at)
                        values (:id,:tenant,:resource,:finding,:terminal,'TRANSITIVE_DEPENDENCY','ACTIVE',now())
                        on conflict (tenant_id,declared_resource_id,finding_id) do update
                        set lifecycle_history=case when ai_bom_resource_vulnerability_links.status='RETIRED'
                            then ai_bom_resource_vulnerability_links.lifecycle_history || jsonb_build_array(jsonb_build_object('status','ACTIVE','at',now(),'revision',:revision))
                            else ai_bom_resource_vulnerability_links.lifecycle_history end,
                            status='ACTIVE', confirmed_at=now(), retired_at=null, retirement_reason=null,
                            via_component_id=excluded.via_component_id
                        returning id
                        """, p, UUID.class);
                desiredLinks.add(link);
                p.put("link", link); p.put("fingerprint", path.fingerprint()); p.put("method", path.method());
                p.put("components", json(path.components())); p.put("relationships", json(path.relationships()));
                p.put("refs", json(path.refs())); p.put("keys", json(path.edgeKeys())); p.put("id", UUID.randomUUID());
                jdbc.update("""
                        insert into ai_bom_correlation_paths
                        (id,tenant_id,declared_resource_id,link_id,source_id,bom_id,source_revision,component_ids,
                        relationship_ids,component_refs,relationship_keys,terminal_component_id,match_method,fingerprint)
                        values (:id,:tenant,:resource,:link,:source,:bom,:revision,cast(:components as jsonb),
                        cast(:relationships as jsonb),cast(:refs as jsonb),cast(:keys as jsonb),:terminal,:method,:fingerprint)
                        on conflict (tenant_id,declared_resource_id,link_id,fingerprint) do update
                        set lifecycle_history=case when ai_bom_correlation_paths.status='RETIRED'
                            then ai_bom_correlation_paths.lifecycle_history || jsonb_build_array(jsonb_build_object('status','ACTIVE','at',now(),'revision',:revision))
                            else ai_bom_correlation_paths.lifecycle_history end,
                            status='ACTIVE', confirmed_at=now(), retired_at=null, retirement_reason=null,
                            bom_id=excluded.bom_id, source_revision=excluded.source_revision,
                            component_ids=excluded.component_ids, relationship_ids=excluded.relationship_ids
                        """, p);
                desired.add(link + "|" + path.fingerprint());
            }
        }
        persistGaps(p, result.gaps());
        var previous = jdbc.queryForList("""
                select id, link_id, fingerprint, component_refs::text as refs, relationship_keys::text as keys
                from ai_bom_correlation_paths where tenant_id=:tenant and declared_resource_id=:resource and status='ACTIVE'
                """, p);
        int withdrawn = 0;
        int retainedUncertainPaths = 0;
        for (var old : previous) {
            if (desired.contains(old.get("link_id") + "|" + old.get("fingerprint"))) continue;
            // Missing root identity or missing source asset prevents any reliable comparison.
            boolean uncertain = !omitted && (result.gaps().stream().anyMatch(g -> g.ref() == null && !"TRAVERSAL_LIMIT_REACHED".equals(g.reason()))
                    || result.preserves(strings(old.get("refs")), strings(old.get("keys"))));
            if (uncertain) { retainedUncertainPaths++; continue; }
            withdrawn++;
            if (retirementEnabled) {
                p.put("path", old.get("id"));
                jdbc.update("update ai_bom_correlation_paths set lifecycle_history=lifecycle_history || jsonb_build_array(jsonb_build_object('status','RETIRED','at',now(),'revision',:revision,'bomId',bom_id,'evidenceRevision',source_revision,'componentIds',component_ids,'relationshipIds',relationship_ids)), status='RETIRED', retired_at=now(), retirement_reason='SOURCE_SUPPORT_WITHDRAWN' where id=:path and tenant_id=:tenant", p);
            }
        }
        // Legacy links without paths survive backfill until a complete unit can establish absence.
        int retiredLinks = 0;
        if (retirementEnabled) {
            p.put("complete", result.complete() || omitted);
            retiredLinks = jdbc.update("""
                    update ai_bom_resource_vulnerability_links l set lifecycle_history=l.lifecycle_history || jsonb_build_array(jsonb_build_object('status','RETIRED','at',now(),'revision',:revision)), status='RETIRED', retired_at=now(),
                    retirement_reason='SOURCE_SUPPORT_WITHDRAWN'
                    where l.tenant_id=:tenant and l.declared_resource_id=:resource and l.status='ACTIVE'
                    and not exists (select 1 from ai_bom_correlation_paths p where p.link_id=l.id and p.status='ACTIVE')
                    and (:complete or exists (select 1 from ai_bom_correlation_paths p where p.link_id=l.id))
                    """, p);
            jdbc.update("""
                    delete from finding_subjects s using ai_bom_resource_vulnerability_links l
                    where l.tenant_id=:tenant and l.declared_resource_id=:resource and l.status='RETIRED'
                    and s.tenant_id=l.tenant_id and s.finding_id=l.finding_id and s.subject_id=l.declared_resource_id
                    and s.subject_type='AI_RESOURCE' and s.subject_role='AFFECTED_AI_RESOURCE'
                    """, p);
        }
        // Repair missing subjects even for pre-existing links and retained uncertain support.
        int repaired = jdbc.update("""
                insert into finding_subjects (id,tenant_id,finding_id,subject_type,subject_id,subject_role)
                select gen_random_uuid(),tenant_id,finding_id,'AI_RESOURCE',declared_resource_id,'AFFECTED_AI_RESOURCE'
                from ai_bom_resource_vulnerability_links where tenant_id=:tenant and declared_resource_id=:resource and status='ACTIVE'
                on conflict do nothing
                """, p);
        long activeAfter = jdbc.queryForObject("select count(*) from ai_bom_resource_vulnerability_links where tenant_id=:tenant and declared_resource_id=:resource and status='ACTIVE'", p, Long.class);
        long reactivatedLinks = desiredLinks.stream().filter(retiredIdsBefore::contains).count();
        log.info("AI-BOM reconciliation tenant={} source={} resource={} revision={} desiredLinks={} desiredPaths={} activeLinksBefore={} activeLinksAfter={} withdrawnPaths={} retainedUncertainPaths={} retirementEnabled={} subjectsRepaired={} retiredLinks={} reactivatedLinks={} gaps={}",
                tenant.getId(), resource.getSourceId(), resource.getId(), snapshot.revision(), desiredLinks.size(), desired.size(),
                activeBefore, activeAfter, withdrawn, retainedUncertainPaths, retirementEnabled, repaired,
                retiredLinks, reactivatedLinks, result.gaps().stream().map(AiBomCorrelationResolver.Gap::reason).sorted().toList());
    }

    private void persistGaps(Map<String, Object> p, Set<AiBomCorrelationResolver.Gap> gaps) {
        jdbc.update("update ai_bom_correlation_gaps set resolved_at=now() where tenant_id=:tenant and declared_resource_id=:resource and resolved_at is null", p);
        for (var gap : gaps) {
            p.put("id", UUID.randomUUID()); p.put("component", gap.component()); p.put("ref", gap.ref()); p.put("reason", gap.reason());
            p.put("fingerprint", AiBomCorrelationResolver.fingerprint(Objects.toString(gap.ref(), "") + "|" + gap.reason()));
            jdbc.update("""
                    insert into ai_bom_correlation_gaps
                    (id,tenant_id,declared_resource_id,source_id,bom_id,source_revision,component_id,component_ref,reason,fingerprint)
                    values (:id,:tenant,:resource,:source,:bom,:revision,:component,:ref,:reason,:fingerprint)
                    on conflict (tenant_id,declared_resource_id,fingerprint) do update
                    set resolved_at=null,bom_id=excluded.bom_id,source_revision=excluded.source_revision,
                        component_id=excluded.component_id
                    """, p);
        }
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordFailure(Tenant tenant, UUID resourceId, UUID sourceId, long capturedRevision) {
        if (!writesEnabled) return;
        Snapshot snapshot = lock(tenant, sourceId, resourceId, capturedRevision);
        if (snapshot == null) return;
        AiBomDeclaredResource resource = resources.findById(resourceId).orElse(null);
        if (resource == null || !tenant.getId().equals(resource.getTenantId()) || !sourceId.equals(resource.getSourceId())) return;
        // Leave previous gaps unresolved as well as all support when a read failed.
        Map<String, Object> p = params(tenant, resource, snapshot);
        p.put("id", UUID.randomUUID());
        jdbc.update("""
                insert into ai_bom_correlation_gaps
                (id,tenant_id,declared_resource_id,source_id,bom_id,source_revision,reason,fingerprint)
                values (:id,:tenant,:resource,:source,:bom,:revision,'RECONCILIATION_FAILED','RECONCILIATION_FAILED')
                on conflict (tenant_id,declared_resource_id,fingerprint) do update set resolved_at=null,source_revision=excluded.source_revision
                """, p);
    }
    private String json(Object value) {
        try { return mapper.writeValueAsString(value); }
        catch (Exception e) { throw new IllegalStateException("Cannot encode correlation evidence", e); }
    }
    private List<String> strings(Object value) {
        try { return mapper.readValue(value.toString(), new TypeReference<List<String>>() { }); }
        catch (Exception e) { throw new IllegalStateException("Cannot read correlation evidence", e); }
    }
}
