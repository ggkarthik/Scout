package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.service.TenantContext;
import java.io.InputStream;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

/** Atomic, tenant-scoped private-preview controls for the Phase 1 policy family. */
@Service
public class AiGridPhase1PreviewService {
    private static final String FAMILY = "AGCF_PHASE_1";
    private static final String VERSION = "1.0.0";
    private static final List<String> GATES = List.of(
            "CATALOG_BROWSER_E2E", "CERTIFICATION_246", "SECURITY_SMOKE",
            "PERFORMANCE_SMOKE", "ROLLBACK_SMOKE", "INTERNAL_CANARY");
    private final NamedParameterJdbcTemplate jdbc;
    private final TransactionTemplate transactions;
    private final ObjectMapper mapper;
    private final AiGridPhase1ReleaseBoardService releaseBoard;

    public AiGridPhase1PreviewService(NamedParameterJdbcTemplate jdbc,
                                      TransactionTemplate transactions,
                                      ObjectMapper mapper,
                                      AiGridPhase1ReleaseBoardService releaseBoard) {
        this.jdbc = jdbc;
        this.transactions = transactions;
        this.mapper = mapper;
        this.releaseBoard = releaseBoard;
    }

    public PreviewStatus status() {
        return TenantContext.runAsPlatform(this::readStatus);
    }

    /** The 246-case private-preview projection of the shipped six-scenario corpus. */
    public PreviewCertificationProfile certificationProfile() {
        return TenantContext.runAsPlatform(() -> {
            try (InputStream in = getClass().getClassLoader().getResourceAsStream(
                    "ai-grid/certification/agcf-phase-1-answer-key-corpus.json")) {
                if (in == null) throw new IllegalStateException("Phase 1 answer-key corpus is missing");
                JsonNode corpus = mapper.readTree(in);
                List<String> posture = List.of("SECURE", "INSECURE", "MISSING_EVIDENCE");
                List<String> correlation = List.of("SECURE", "INSECURE", "MISSING_EVIDENCE",
                        "STALE_EVIDENCE", "CAPABILITY_FAILURE", "PROXY_VS_VERIFIED");
                List<String> caseKeys = new ArrayList<>();
                int posturePolicies = 0;
                int correlationPolicies = 0;
                for (JsonNode policy : corpus.path("policies")) {
                    String policyId = policy.path("policyId").asText();
                    String workflow = jdbc.queryForObject("select workflow_class from platform.ai_grid_policy_versions "
                            + "where release_family=:family and policy_id=:policy and version=:version",
                            Map.of("family", FAMILY, "policy", policyId, "version", VERSION), String.class);
                    boolean isCorrelation = "VALIDATED_EXPOSURE".equals(workflow);
                    if (isCorrelation) correlationPolicies++; else posturePolicies++;
                    List<String> selected = isCorrelation ? correlation : posture;
                    corpus.path("cases").forEach(c -> {
                        if (policyId.equals(c.path("policyId").asText())
                                && selected.contains(c.path("scenario").asText())) {
                            caseKeys.add(c.path("caseKey").asText());
                        }
                    });
                }
                caseKeys.sort(Comparator.naturalOrder());
                return new PreviewCertificationProfile(corpus.path("sourceManifestDigest").asText(),
                        digest(caseKeys), posturePolicies, correlationPolicies, caseKeys.size(),
                        Map.of("SECURE", posturePolicies + correlationPolicies,
                                "INSECURE", posturePolicies + correlationPolicies,
                                "MISSING_EVIDENCE", posturePolicies + correlationPolicies,
                                "STALE_EVIDENCE", correlationPolicies,
                                "CAPABILITY_FAILURE", correlationPolicies,
                                "PROXY_VS_VERIFIED", correlationPolicies));
            } catch (Exception ex) {
                throw new IllegalStateException("Unable to build Phase 1 preview certification profile", ex);
            }
        });
    }

    public PreviewGate recordGate(String gateKey, GateCommand command, String actor) {
        if (!GATES.contains(gateKey)) throw badRequest("Unknown preview gate: " + gateKey);
        if (command == null || blank(command.evidenceReference()) == null) throw badRequest("evidenceReference is required");
        if (!List.of("PASSED", "FAILED").contains(command.status())) throw badRequest("status must be PASSED or FAILED");
        if ("CERTIFICATION_246".equals(gateKey) && "PASSED".equals(command.status())) {
            Map<String, Object> results = command.results() == null ? Map.of() : command.results();
            if (number(results, "caseCount", -1) != 246
                    || number(results, "matchedCases", -1) != 246
                    || number(results, "falsePasses", -1) != 0
                    || !Boolean.TRUE.equals(results.get("engineProvenance"))
                    || !Boolean.TRUE.equals(results.get("digestMatches"))) {
                throw badRequest("CERTIFICATION_246 requires 246 matched engine-backed cases, zero false PASS results, provenance, and digest binding");
            }
        }
        return TenantContext.runAsPlatform(() -> transactions.execute(status -> {
            String results = json(command.results() == null ? Map.of() : command.results());
            jdbc.update("""
                    insert into platform.ai_grid_phase_1_preview_gate_evidence
                        (gate_key,status,evidence_ref,results_json,recorded_by,recorded_at)
                    values (:key,:state,:evidence,cast(:results as jsonb),:actor,now())
                    on conflict (gate_key) do update set status=excluded.status,
                        evidence_ref=excluded.evidence_ref, results_json=excluded.results_json,
                        recorded_by=excluded.recorded_by, recorded_at=now()
                    """, new MapSqlParameterSource().addValue("key", gateKey)
                    .addValue("state", command.status()).addValue("evidence", command.evidenceReference())
                    .addValue("results", results).addValue("actor", actor));
            return gate(gateKey);
        }));
    }

    /** Executes the catalog-side portion of the browser gate and records its database evidence. */
    public PreviewGate runCatalogCheck(String actor) {
        return TenantContext.runAsPlatform(() -> {
            Map<String, Object> results = new LinkedHashMap<>();
            Integer total = jdbc.queryForObject("select count(*) from platform.ai_grid_policy_versions "
                    + "where release_family=:family and version=:version", Map.of("family", FAMILY, "version", VERSION), Integer.class);
            Map<String, Integer> providers = jdbc.query("select provider,count(*) from platform.ai_grid_policy_versions "
                    + "where release_family=:family and version=:version group by provider", Map.of("family", FAMILY, "version", VERSION),
                    (rs, n) -> Map.entry(rs.getString(1), rs.getInt(2))).stream()
                    .collect(java.util.stream.Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
            Map<String, Integer> selections = jdbc.query("select d.default_selection,count(*) from platform.ai_grid_policy_distribution d "
                    + "join platform.ai_grid_policy_versions p using(policy_id) where p.release_family=:family and p.version=:version "
                    + "group by d.default_selection", Map.of("family", FAMILY, "version", VERSION),
                    (rs, n) -> Map.entry(rs.getString(1), rs.getInt(2))).stream()
                    .collect(java.util.stream.Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
            boolean passed = total != null && total == 76
                    && Map.of("AWS", 38, "AZURE", 32, "MULTI_CLOUD", 6).equals(providers)
                    && Map.of("REQUIRED", 26, "ENABLED", 24, "DISABLED", 26).equals(selections);
            results.put("totalPolicies", total);
            results.put("providerCounts", providers);
            results.put("defaultSelections", selections);
            return recordGate("CATALOG_BROWSER_E2E", new GateCommand(passed ? "PASSED" : "FAILED",
                    "preview-catalog-check", results), actor);
        });
    }

    /** Adapts the existing real-run performance gate to the private-preview gate store. */
    public PreviewGate runPerformanceCheck(UUID tenantId, UUID baselineRunId, UUID candidateRunId, String actor) {
        AiGridPhase1ReleaseBoardService.Gate gate = releaseBoard.recordPerformanceComparison(
                tenantId, baselineRunId, candidateRunId, actor);
        return recordGate("PERFORMANCE_SMOKE", new GateCommand(gate.status(),
                "release-board://" + gate.gateKey(), readJson(gate.evidenceJson())), actor);
    }

    /** Runs one real rollback drill per provider and only passes after all three restore cleanly. */
    public PreviewGate runRollbackChecks(Map<String, String> policyByProvider, String actor) {
        if (policyByProvider == null || !policyByProvider.keySet().equals(Set.of("AWS", "AZURE", "MULTI_CLOUD"))) {
            throw badRequest("policyByProvider must contain AWS, AZURE, and MULTI_CLOUD");
        }
        Map<String, Object> results = new LinkedHashMap<>();
        boolean passed = true;
        for (String provider : List.of("AWS", "AZURE", "MULTI_CLOUD")) {
            AiGridPhase1ReleaseBoardService.Gate gate = releaseBoard.demonstrateRollback(
                    provider, policyByProvider.get(provider), actor);
            passed &= "PASSED".equals(gate.status());
            results.put(provider, readJson(gate.evidenceJson()));
        }
        return recordGate("ROLLBACK_SMOKE", new GateCommand(passed ? "PASSED" : "FAILED",
                "release-board://rollback-drills", results), actor);
    }

    /** Records the internal canary only from a provider run whose metrics passed the real gate. */
    public PreviewGate runInternalCanary(UUID tenantId, UUID runId, String actor) {
        AiGridPhase1ReleaseBoardService.Gate gate = releaseBoard.recordCanaryRun(tenantId, runId, actor);
        return recordGate("INTERNAL_CANARY", new GateCommand(gate.status(),
                "release-board://" + gate.gateKey(), readJson(gate.evidenceJson())), actor);
    }

    public PreviewStatus promoteInternal(UUID tenantId, String actor) {
        if (tenantId == null) throw badRequest("internalTenantId is required");
        return TenantContext.runAsPlatform(() -> transactions.execute(status -> {
            validateCatalog();
            validateTenant(tenantId);
            requireGates(List.of("CATALOG_BROWSER_E2E", "CERTIFICATION_246", "SECURITY_SMOKE"));
            updateDistribution(List.of(tenantId), actor);
            jdbc.update("""
                    update platform.ai_grid_phase_1_preview_release
                       set state='PROMOTED', internal_tenant_id=:tenant,
                           approved_cohort_json=cast(:cohort as jsonb),
                           last_approved_cohort_json=cast(:cohort as jsonb),
                           approved_by=:actor, approved_at=now(), updated_at=now()
                     where release_family=:family
                    """, new MapSqlParameterSource().addValue("tenant", tenantId)
                    .addValue("cohort", json(List.of(tenantId.toString()))).addValue("actor", actor)
                    .addValue("family", FAMILY));
            return readStatus();
        }));
    }

    public PreviewStatus replaceCohort(List<UUID> tenantIds, String actor) {
        if (tenantIds == null || tenantIds.isEmpty()) throw badRequest("cohort must not be empty");
        if (tenantIds.stream().distinct().count() != tenantIds.size()) throw badRequest("cohort contains duplicates");
        return TenantContext.runAsPlatform(() -> transactions.execute(status -> {
            PreviewRelease release = release();
            if (release.internalTenantId() == null || !tenantIds.contains(release.internalTenantId())) {
                throw conflict("cohort must include the internal canary tenant");
            }
            validateCatalog();
            tenantIds.forEach(this::validateTenant);
            if (!"PROMOTED".equals(release.state())) throw conflict("private preview is not promoted");
            updateDistribution(tenantIds, actor);
            String cohort = json(tenantIds.stream().map(UUID::toString).toList());
            jdbc.update("""
                    update platform.ai_grid_phase_1_preview_release
                       set approved_cohort_json=cast(:cohort as jsonb),
                           last_approved_cohort_json=cast(:cohort as jsonb),
                           approved_by=:actor, approved_at=now(), updated_at=now()
                     where release_family=:family
                    """, Map.of("cohort", cohort, "actor", actor, "family", FAMILY));
            return readStatus();
        }));
    }

    public PreviewStatus pause(String actor) {
        return TenantContext.runAsPlatform(() -> transactions.execute(status -> {
            jdbc.update("""
                    update platform.ai_grid_policy_distribution d
                       set available=false, rollout_stage='PAUSED', canary_tenant_ids_json='[]'::jsonb,
                           updated_by=:actor, updated_at=now()
                     where exists (select 1 from platform.ai_grid_policy_versions p
                                    where p.policy_id=d.policy_id and p.release_family=:family)
                    """, Map.of("actor", actor, "family", FAMILY));
            jdbc.update("update platform.ai_grid_phase_1_preview_release set state='PAUSED', approved_cohort_json='[]'::jsonb, updated_at=now() where release_family=:family", Map.of("family", FAMILY));
            return readStatus();
        }));
    }

    public PreviewStatus resume(String actor) {
        return TenantContext.runAsPlatform(() -> transactions.execute(status -> {
            PreviewRelease release = release();
            validateCatalog();
            if (!currentManifest().equals(release.manifestDigest())) throw conflict("manifest digest changed; preview approval is invalid");
            List<UUID> cohort = parseCohort(release.lastApprovedCohortJson());
            if (cohort.isEmpty()) throw conflict("no last approved cohort is available");
            cohort.forEach(this::validateTenant);
            updateDistribution(cohort, actor);
            jdbc.update("update platform.ai_grid_phase_1_preview_release set state='PROMOTED', approved_cohort_json=last_approved_cohort_json, updated_at=now() where release_family=:family", Map.of("family", FAMILY));
            return readStatus();
        }));
    }

    private void validateCatalog() {
        Integer total = jdbc.queryForObject("select count(*) from platform.ai_grid_policy_versions where release_family=:family and version=:version", Map.of("family", FAMILY, "version", VERSION), Integer.class);
        if (total == null || total != 76) throw conflict("Phase 1 catalog must contain exactly 76 current packages");
        Map<String, Integer> providers = jdbc.query("select provider,count(*) from platform.ai_grid_policy_versions where release_family=:family and version=:version group by provider", Map.of("family", FAMILY, "version", VERSION), (rs, n) -> Map.entry(rs.getString(1), rs.getInt(2))).stream().collect(java.util.stream.Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
        if (!Map.of("AWS", 38, "AZURE", 32, "MULTI_CLOUD", 6).equals(providers)) throw conflict("Phase 1 provider counts do not match 38/32/6");
        Map<String, Integer> selections = jdbc.query("select default_selection,count(*) from platform.ai_grid_policy_distribution d join platform.ai_grid_policy_versions p using(policy_id) where p.release_family=:family and p.version=:version group by default_selection", Map.of("family", FAMILY, "version", VERSION), (rs, n) -> Map.entry(rs.getString(1), rs.getInt(2))).stream().collect(java.util.stream.Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
        if (!Map.of("REQUIRED", 26, "ENABLED", 24, "DISABLED", 26).equals(selections)) throw conflict("Phase 1 default-selection counts do not match 26/24/26");
    }

    private void validateTenant(UUID tenantId) {
        Integer valid = jdbc.queryForObject("""
                select count(*) from platform.tenants t join platform.tenant_schema_versions v on v.tenant_id=t.id
                 where t.id=:id and t.status='ACTIVE' and t.deleted_at is null and t.purged_at is null
                   and v.status='CURRENT' and v.current_version=v.target_version and v.current_version>=67
                """, Map.of("id", tenantId), Integer.class);
        if (valid == null || valid != 1) throw conflict("tenant is inactive, unknown, deleted, or schema-stale: " + tenantId);
    }

    private void requireGates(List<String> required) {
        Integer failed = jdbc.queryForObject("select count(*) from platform.ai_grid_phase_1_preview_gate_evidence where gate_key in (:keys) and status <> 'PASSED'", Map.of("keys", required), Integer.class);
        if (failed != null && failed > 0) throw conflict("preview gates are incomplete");
    }

    private void updateDistribution(List<UUID> cohort, String actor) {
        String ids = json(cohort.stream().map(UUID::toString).toList());
        jdbc.update("""
                update platform.ai_grid_policy_versions set lifecycle='CANARY'
                 where release_family=:family and version=:version
                """, Map.of("family", FAMILY, "version", VERSION));
        jdbc.update("""
                update platform.ai_grid_policy_distribution d
                   set available=true, rollout_stage='CANARY', canary_tenant_ids_json=cast(:cohort as jsonb),
                       pinned_version=:version, updated_by=:actor, updated_at=now()
                 where exists (select 1 from platform.ai_grid_policy_versions p
                                where p.policy_id=d.policy_id and p.release_family=:family and p.version=:version)
                """, new MapSqlParameterSource().addValue("cohort", ids).addValue("version", VERSION)
                .addValue("actor", actor).addValue("family", FAMILY));
    }

    private PreviewStatus readStatus() {
        PreviewRelease release = release();
        Map<String, Integer> providers = jdbc.query("select provider,count(*) from platform.ai_grid_policy_versions where release_family=:family and version=:version group by provider", Map.of("family", FAMILY, "version", VERSION), (rs, n) -> Map.entry(rs.getString(1), rs.getInt(2))).stream().collect(java.util.stream.Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
        List<PreviewGate> gates = GATES.stream().map(this::gate).toList();
        List<String> blockers = new ArrayList<>();
        if (release.totalPolicies() != 76) blockers.add("CATALOG_COUNT");
        if (!currentManifest().equals(release.manifestDigest())) blockers.add("MANIFEST_DIGEST");
        gates.stream().filter(g -> !"PASSED".equals(g.status())).forEach(g -> blockers.add(g.gateKey()));
        return new PreviewStatus(release.manifestDigest(), release.totalPolicies(), providers, gates,
                parseCohort(release.approvedCohortJson()), release.internalTenantId(), release.state(), blockers);
    }

    private PreviewRelease release() {
        return jdbc.query("select manifest_digest,total_policies,state,internal_tenant_id,approved_cohort_json::text,last_approved_cohort_json::text from platform.ai_grid_phase_1_preview_release where release_family=:family", Map.of("family", FAMILY), rs -> rs.next() ? new PreviewRelease(rs.getString(1), rs.getInt(2), rs.getString(3), rs.getObject(4, UUID.class), rs.getString(5), rs.getString(6)) : null);
    }
    private PreviewGate gate(String key) {
        return jdbc.query("select gate_key,status,evidence_ref,results_json::text,recorded_by,recorded_at from platform.ai_grid_phase_1_preview_gate_evidence where gate_key=:key", Map.of("key", key), rs -> rs.next() ? new PreviewGate(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4), rs.getString(5), rs.getTimestamp(6).toInstant()) : new PreviewGate(key, "PENDING", null, "{}", null, null));
    }
    private String currentManifest() {
        return jdbc.queryForObject("select md5(string_agg(coalesce(package_digest, ''), ',' order by policy_id, version)) from platform.ai_grid_policy_versions where release_family=:family", Map.of("family", FAMILY), String.class);
    }
    private String digest(List<String> values) {
        try {
            byte[] bytes = MessageDigest.getInstance("SHA-256")
                    .digest(String.join("\n", values).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder out = new StringBuilder();
            for (byte value : bytes) out.append(String.format("%02x", value));
            return out.toString();
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to digest preview profile", ex);
        }
    }
    private List<UUID> parseCohort(String json) {
        try { return mapper.readValue(json == null ? "[]" : json, mapper.getTypeFactory().constructCollectionType(List.class, UUID.class)); }
        catch (Exception ex) { throw new IllegalStateException("Invalid preview cohort JSON", ex); }
    }
    private String json(Object value) {
        try { return mapper.writeValueAsString(value); }
        catch (JsonProcessingException ex) { throw new IllegalStateException("Unable to encode preview JSON", ex); }
    }
    private Map<String, Object> readJson(String value) {
        try { return value == null ? Map.of() : mapper.readValue(value, mapper.getTypeFactory().constructMapType(Map.class, String.class, Object.class)); }
        catch (Exception ex) { return Map.of("evidence", value == null ? "" : value); }
    }
    private String blank(String value) { return value == null || value.isBlank() ? null : value.trim(); }
    private int number(Map<String, Object> values, String key, int fallback) {
        Object value = values.get(key);
        if (value instanceof Number number) return number.intValue();
        return value instanceof String text && text.matches("-?\\d+") ? Integer.parseInt(text) : fallback;
    }
    private ResponseStatusException badRequest(String message) { return new ResponseStatusException(HttpStatus.BAD_REQUEST, message); }
    private ResponseStatusException conflict(String message) { return new ResponseStatusException(HttpStatus.CONFLICT, message); }

    public record GateCommand(String status, String evidenceReference, Map<String, Object> results) {}
    public record PreviewStatus(String manifestDigest, int totalPolicies, Map<String, Integer> providerCounts,
                                List<PreviewGate> gates, List<UUID> approvedCohort, UUID internalTenantId,
                                String state, List<String> blockers) {}
    public record PreviewGate(String gateKey, String status, String evidenceReference, String resultsJson,
                              String recordedBy, Instant recordedAt) {}
    public record PreviewCertificationProfile(String sourceManifestDigest, String profileDigest,
                                               int posturePolicies, int correlationPolicies, int totalCases,
                                               Map<String, Integer> casesByScenario) {}
    private record PreviewRelease(String manifestDigest, int totalPolicies, String state, UUID internalTenantId,
                                  String approvedCohortJson, String lastApprovedCohortJson) {}
}
