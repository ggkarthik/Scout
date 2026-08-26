package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantService;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Applies the approved Phase 1 legacy-detector ledger to one tenant at a time.
 * It is intentionally operator-invoked: migration never runs as a side effect of
 * publishing a policy or provisioning a tenant.
 */
@Service
public class AiGridPhase1PolicyMigrationService {
    private static final String ACTOR_REASON_PREFIX = "AI_GRID_PHASE_1_LEDGER";
    private static final String LEDGER_VERSION = "AGCF_PHASE_1_V1";

    private final NamedParameterJdbcTemplate jdbc;
    private final TenantService tenants;
    private final TenantSchemaExecutionService tenantExecution;
    private final TransactionTemplate transactions;
    private final ObjectMapper objectMapper;

    public AiGridPhase1PolicyMigrationService(NamedParameterJdbcTemplate jdbc, TenantService tenants,
                                               TenantSchemaExecutionService tenantExecution,
                                               TransactionTemplate transactions, ObjectMapper objectMapper) {
        this.jdbc = jdbc;
        this.tenants = tenants;
        this.tenantExecution = tenantExecution;
        this.transactions = transactions;
        this.objectMapper = objectMapper;
    }

    public MigrationPreview preview(UUID tenantId) {
        Tenant tenant = tenants.requireTenantUuid(tenantId);
        return tenantExecution.run(tenant, () -> plan(tenant));
    }

    public MigrationResult apply(UUID tenantId, String actor) {
        Tenant tenant = tenants.requireTenantUuid(tenantId);
        return tenantExecution.run(tenant, () -> transactions.execute(status -> {
            MigrationPreview preview = plan(tenant);
            if (!preview.blockers().isEmpty()) {
                throw new IllegalStateException("Phase 1 policy migration is blocked: " + String.join("; ", preview.blockers()));
            }
            for (MigrationAction action : preview.actions()) {
                apply(tenant, action, actor == null || actor.isBlank() ? "platform-owner" : actor);
            }
            MigrationResult result = new MigrationResult(preview.tenantId(), preview.legacySelections(), preview.selectionCopies(),
                    preview.retirements(), preview.scopeCopies(), preview.overrideCopies(), preview.parameterManualReviews(),
                    preview.openFindingsToClose(), preview.openFindingsReconciled(), preview.actions());
            if (!result.actions().isEmpty()) audit(result, actor == null || actor.isBlank() ? "platform-owner" : actor);
            return result;
        }));
    }

    private MigrationPreview plan(Tenant tenant) {
        List<LedgerEntry> ledger = ledger();
        Set<String> legacyIds = ledger.stream().map(LedgerEntry::legacyDetectorId).collect(java.util.stream.Collectors.toSet());
        if (legacyIds.isEmpty()) return new MigrationPreview(tenant.getId(), 0, 0, 0, 0, 0, 0, 0, 0, List.of(), List.of());

        Map<String, String> selections = selectionMap(legacyIds);
        Set<String> selectedLegacyIds = selections.keySet();
        Set<String> successors = ledger.stream().filter(entry -> selectedLegacyIds.contains(entry.legacyDetectorId()))
                .flatMap(entry -> entry.successorPolicyIds().stream()).collect(java.util.stream.Collectors.toSet());
        Map<String, String> defaults = successorDefaults(successors);
        Map<String, String> currentSelections = selectionMap(successors);
        Map<String, Scope> scopes = scopes(legacyIds, successors);
        Map<String, List<Override>> overrides = overrides(legacyIds, successors);
        Set<String> parameterized = parameterizedPolicies(legacyIds);
        List<String> blockers = new ArrayList<>();
        List<MigrationAction> actions = new ArrayList<>();
        int selectionCopies = 0;
        int retirements = 0;
        int scopeCopies = 0;
        int overrideCopies = 0;
        int parameterManualReviews = 0;
        int openFindingsToClose = 0;
        int openFindingsReconciled = 0;

        for (LedgerEntry entry : ledger) {
            String sourceSelection = selections.get(entry.legacyDetectorId());
            if (sourceSelection == null) continue;
            if ("RETIRED_INSUFFICIENT_EVIDENCE".equals(entry.disposition())) {
                int findings = openFindingCount(entry.legacyDetectorId());
                actions.add(MigrationAction.retire(entry, sourceSelection, findings, scopes.containsKey(entry.legacyDetectorId()),
                        overrides.getOrDefault(entry.legacyDetectorId(), List.of()).size(), parameterized.contains(entry.legacyDetectorId())));
                retirements++;
                openFindingsToClose += findings;
                continue;
            }
            if (entry.successorPolicyIds().isEmpty()) {
                blockers.add(entry.legacyDetectorId() + " has no approved successor");
                continue;
            }
            List<String> missing = entry.successorPolicyIds().stream().filter(id -> !defaults.containsKey(id)).toList();
            if (!missing.isEmpty()) {
                blockers.add(entry.legacyDetectorId() + " successors are not published and distributed: " + String.join(", ", missing));
                continue;
            }

            List<SelectionCopy> copies = new ArrayList<>();
            for (String successor : entry.successorPolicyIds()) {
                if (currentSelections.containsKey(successor)) continue;
                String effectiveSelection = "REQUIRED".equals(defaults.get(successor)) ? "REQUIRED" : sourceSelection;
                copies.add(new SelectionCopy(successor, effectiveSelection));
                currentSelections.put(successor, effectiveSelection);
                selectionCopies++;
            }

            ScopeCopy scopeCopy = null;
            List<OverrideCopy> copiedOverrides = List.of();
            boolean manualConfigurationReview = false;
            String reconcileToPolicyId = null;
            int findingsToReconcile = 0;
            if ("ONE_TO_ONE_REPLACEMENT".equals(entry.disposition())) {
                String successor = entry.successorPolicyIds().get(0);
                reconcileToPolicyId = successor;
                findingsToReconcile = openFindingCount(entry.legacyDetectorId());
                openFindingsReconciled += findingsToReconcile;
                Scope sourceScope = scopes.get(entry.legacyDetectorId());
                if (sourceScope != null && !scopes.containsKey(successor)) {
                    scopeCopy = new ScopeCopy(successor, sourceScope);
                    scopes.put(successor, sourceScope);
                    scopeCopies++;
                }
                List<OverrideCopy> candidates = new ArrayList<>();
                Set<UUID> targetArtifacts = overrides.getOrDefault(successor, List.of()).stream()
                        .map(Override::artifactId).collect(java.util.stream.Collectors.toSet());
                for (Override override : overrides.getOrDefault(entry.legacyDetectorId(), List.of())) {
                    if (targetArtifacts.add(override.artifactId())) {
                        candidates.add(new OverrideCopy(successor, override));
                        overrideCopies++;
                    }
                }
                copiedOverrides = List.copyOf(candidates);
                if (parameterized.contains(entry.legacyDetectorId())) {
                    manualConfigurationReview = true;
                    parameterManualReviews++;
                }
            } else if (scopes.containsKey(entry.legacyDetectorId())
                    || !overrides.getOrDefault(entry.legacyDetectorId(), List.of()).isEmpty()
                    || parameterized.contains(entry.legacyDetectorId())) {
                // A split has no safe way to infer which successor should own a scope or override.
                manualConfigurationReview = true;
                parameterManualReviews++;
            }
            actions.add(MigrationAction.replace(entry, sourceSelection, copies, scopeCopy, copiedOverrides,
                    manualConfigurationReview, reconcileToPolicyId, findingsToReconcile));
        }
        actions.sort(Comparator.comparing(MigrationAction::legacyDetectorId));
        return new MigrationPreview(tenant.getId(), selectedLegacyIds.size(), selectionCopies, retirements, scopeCopies,
                overrideCopies, parameterManualReviews, openFindingsToClose, openFindingsReconciled,
                List.copyOf(blockers), List.copyOf(actions));
    }

    private void apply(Tenant tenant, MigrationAction action, String actor) {
        String reason = ACTOR_REASON_PREFIX + ":" + action.disposition() + ":" + action.legacyDetectorId();
        for (SelectionCopy copy : action.selectionCopies()) {
            jdbc.update("""
                    insert into ai_grid_policy_selections (policy_id, tenant_id, selection, updated_by, reason)
                    values (:policyId, :tenantId, :selection, :actor, :reason)
                    on conflict (policy_id) do nothing
                    """, parameters(tenant, actor, reason).addValue("policyId", copy.policyId()).addValue("selection", copy.selection()));
            insertHistory(tenant, copy.policyId(), null, copy.selection(), actor, reason);
        }
        if (action.scopeCopy() != null) {
            ScopeCopy copy = action.scopeCopy();
            jdbc.update("""
                    insert into ai_grid_policy_scopes (policy_id, tenant_id, mode, condition_logic, conditions_json, updated_by)
                    values (:policyId, :tenantId, :mode, :logic, cast(:conditions as jsonb), :actor)
                    on conflict (policy_id) do nothing
                    """, parameters(tenant, actor, reason).addValue("policyId", copy.policyId()).addValue("mode", copy.scope().mode())
                    .addValue("logic", copy.scope().conditionLogic()).addValue("conditions", copy.scope().conditionsJson()));
        }
        for (OverrideCopy copy : action.overrideCopies()) {
            jdbc.update("""
                    insert into ai_grid_policy_artifact_overrides
                        (id, tenant_id, policy_id, artifact_id, override, reason, created_by)
                    values (:id, :tenantId, :policyId, :artifactId, :override, :overrideReason, :actor)
                    on conflict (tenant_id, policy_id, artifact_id) do nothing
                    """, parameters(tenant, actor, reason).addValue("id", UUID.randomUUID()).addValue("policyId", copy.policyId())
                    .addValue("artifactId", copy.override().artifactId()).addValue("override", copy.override().override())
                    .addValue("overrideReason", copy.override().reason()));
        }
        if (action.reconcileToPolicyId() != null) {
            reconcileFindingsToSuccessor(tenant, action.legacyDetectorId(), action.reconcileToPolicyId());
        }
        if ("RETIRED_INSUFFICIENT_EVIDENCE".equals(action.disposition())) {
            jdbc.update("delete from ai_grid_policy_scopes where policy_id = :policyId", Map.of("policyId", action.legacyDetectorId()));
            jdbc.update("delete from ai_grid_policy_artifact_overrides where policy_id = :policyId", Map.of("policyId", action.legacyDetectorId()));
            jdbc.update("delete from ai_grid_policy_parameters where policy_id = :policyId", Map.of("policyId", action.legacyDetectorId()));
            jdbc.update("""
                    update findings set status = 'AUTO_CLOSED', decision_state = 'NOT_AFFECTED', closed_at = now(),
                        closed_reason = :closureReason, updated_at = now()
                     where policy_id = :policyId and status = 'OPEN'
                    """, Map.of("policyId", action.legacyDetectorId(), "closureReason", action.closureReason()));
        } else if (action.removeLegacyConfiguration()) {
            jdbc.update("delete from ai_grid_policy_scopes where policy_id = :policyId", Map.of("policyId", action.legacyDetectorId()));
            jdbc.update("delete from ai_grid_policy_artifact_overrides where policy_id = :policyId", Map.of("policyId", action.legacyDetectorId()));
            jdbc.update("delete from ai_grid_policy_parameters where policy_id = :policyId", Map.of("policyId", action.legacyDetectorId()));
        }
        jdbc.update("delete from ai_grid_policy_selections where policy_id = :policyId", Map.of("policyId", action.legacyDetectorId()));
        insertHistory(tenant, action.legacyDetectorId(), action.sourceSelection(), "DISABLED", actor, reason);
    }

    private MapSqlParameterSource parameters(Tenant tenant, String actor, String reason) {
        return new MapSqlParameterSource().addValue("tenantId", tenant.getId()).addValue("actor", actor).addValue("reason", reason);
    }

    private void audit(MigrationResult result, String actor) {
        try {
            jdbc.update("""
                    insert into platform.ai_grid_phase_1_tenant_migration_audit
                        (id, tenant_id, ledger_version, applied_by, legacy_selection_count, selection_copy_count,
                         retirement_count, open_findings_closed, manual_configuration_review_count, actions_json)
                    values (:id, :tenantId, :ledgerVersion, :actor, :legacySelections, :selectionCopies,
                            :retirements, :findingsClosed, :manualReviews, cast(:actions as jsonb))
                    """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", result.tenantId())
                    .addValue("ledgerVersion", LEDGER_VERSION).addValue("actor", actor)
                    .addValue("legacySelections", result.legacySelections()).addValue("selectionCopies", result.selectionCopies())
                    .addValue("retirements", result.retirements()).addValue("findingsClosed", result.openFindingsToClose())
                    .addValue("manualReviews", result.parameterManualReviews()).addValue("actions", objectMapper.writeValueAsString(result.actions())));
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to record the Phase 1 tenant migration audit", ex);
        }
    }

    private void insertHistory(Tenant tenant, String policyId, String previous, String selection, String actor, String reason) {
        jdbc.update("""
                insert into ai_grid_policy_selection_history
                    (id, tenant_id, policy_id, previous_selection, selection, actor, reason)
                values (:id, :tenantId, :policyId, :previous, :selection, :actor, :reason)
                """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                .addValue("policyId", policyId).addValue("previous", previous).addValue("selection", selection)
                .addValue("actor", actor).addValue("reason", reason));
    }

    private List<LedgerEntry> ledger() {
        return jdbc.query("""
                select legacy_detector_id, disposition, successor_policy_ids_json::text, closure_reason
                  from platform.ai_grid_policy_migration_ledger
                 where legacy_detector_kind = 'POSTURE_POLICY'
                 order by legacy_detector_id
                """, (rs, row) -> new LedgerEntry(rs.getString(1), rs.getString(2), readIds(rs.getString(3)), rs.getString(4)));
    }

    private List<String> readIds(String value) {
        try { return objectMapper.readValue(value, new TypeReference<List<String>>() {}); }
        catch (Exception ex) { throw new IllegalStateException("Invalid Phase 1 migration ledger successor list", ex); }
    }

    private Map<String, String> selectionMap(Set<String> policyIds) {
        if (policyIds.isEmpty()) return new HashMap<>();
        return jdbc.query("select policy_id, selection from ai_grid_policy_selections where policy_id in (:ids)",
                Map.of("ids", policyIds), rs -> {
                    Map<String, String> result = new HashMap<>();
                    while (rs.next()) result.put(rs.getString(1), rs.getString(2));
                    return result;
                });
    }

    private Map<String, String> successorDefaults(Set<String> policyIds) {
        if (policyIds.isEmpty()) return Map.of();
        return jdbc.query("""
                select d.policy_id, d.default_selection from platform.ai_grid_policy_distribution d
                 where d.policy_id in (:ids) and d.available = true and d.rollout_stage = 'GENERAL_AVAILABILITY'
                   and exists (select 1 from platform.ai_grid_policy_versions p
                                where p.policy_id=d.policy_id and p.lifecycle='PUBLISHED')
                """, Map.of("ids", policyIds), rs -> {
                    Map<String, String> result = new HashMap<>();
                    while (rs.next()) result.put(rs.getString(1), rs.getString(2));
                    return result;
                });
    }

    private Map<String, Scope> scopes(Set<String> legacyIds, Set<String> successors) {
        Set<String> ids = new HashSet<>(legacyIds); ids.addAll(successors);
        return jdbc.query("select policy_id, mode, condition_logic, conditions_json::text from ai_grid_policy_scopes where policy_id in (:ids)",
                Map.of("ids", ids), rs -> {
                    Map<String, Scope> result = new HashMap<>();
                    while (rs.next()) result.put(rs.getString(1), new Scope(rs.getString(2), rs.getString(3), rs.getString(4)));
                    return result;
                });
    }

    private Map<String, List<Override>> overrides(Set<String> legacyIds, Set<String> successors) {
        Set<String> ids = new HashSet<>(legacyIds); ids.addAll(successors);
        return jdbc.query("select policy_id, artifact_id, override, reason from ai_grid_policy_artifact_overrides where policy_id in (:ids)",
                Map.of("ids", ids), rs -> {
                    Map<String, List<Override>> result = new HashMap<>();
                    while (rs.next()) result.computeIfAbsent(rs.getString(1), ignored -> new ArrayList<>())
                            .add(new Override(rs.getObject(2, UUID.class), rs.getString(3), rs.getString(4)));
                    return result;
                });
    }

    private Set<String> parameterizedPolicies(Set<String> ids) {
        if (ids.isEmpty()) return Set.of();
        return new HashSet<>(jdbc.query("""
                select policy_id from ai_grid_policy_parameters
                 where policy_id in (:ids) and parameters_json <> '{}'::jsonb
                """, Map.of("ids", ids), (rs, row) -> rs.getString(1)));
    }

    private int openFindingCount(String policyId) {
        Integer count = jdbc.queryForObject("select count(*) from findings where policy_id = :policyId and status = 'OPEN'",
                Map.of("policyId", policyId), Integer.class);
        return count == null ? 0 : count;
    }

    /**
     * Re-keys the legacy detector's open findings onto its ONE_TO_ONE replacement so the
     * successor adapter reconciles them on its next assessment instead of opening duplicates.
     * The finding identity is {@code sha256(tenant|AI_POSTURE|policyId|ARTIFACT|subjectId)};
     * updating policy_id + fingerprint to the successor's values keeps status/owner/history/
     * display id intact. When the successor already owns that artifact's finding (fingerprint
     * collision on the unique (tenant_id, fingerprint) index), the legacy row is the duplicate
     * and is closed as superseded rather than re-keyed. Runs inside the tenant schema context.
     */
    private void reconcileFindingsToSuccessor(Tenant tenant, String legacyPolicyId, String successorPolicyId) {
        List<FindingSubject> open = jdbc.query("""
                select f.id, fs.subject_id
                  from findings f
                  join finding_subjects fs on fs.finding_id = f.id
                                          and fs.subject_type = 'ARTIFACT'
                                          and fs.subject_role = 'PRIMARY'
                 where f.policy_id = :legacy and f.status = 'OPEN'
                """, Map.of("legacy", legacyPolicyId),
                (rs, row) -> new FindingSubject(rs.getObject(1, UUID.class), rs.getObject(2, UUID.class)));
        for (FindingSubject finding : open) {
            String successorFingerprint =
                    AiGridAssessmentService.postureFindingFingerprint(tenant.getId(), successorPolicyId, finding.subjectId());
            Integer collision = jdbc.queryForObject(
                    "select count(*) from findings where fingerprint = :fp and id <> :id",
                    Map.of("fp", successorFingerprint, "id", finding.findingId()), Integer.class);
            if (collision != null && collision > 0) {
                jdbc.update("""
                        update findings set status = 'AUTO_CLOSED', decision_state = 'NOT_AFFECTED', closed_at = now(),
                            closed_reason = 'SUPERSEDED_BY_REPLACEMENT', updated_at = now()
                         where id = :id and status = 'OPEN'
                        """, Map.of("id", finding.findingId()));
            } else {
                jdbc.update("""
                        update findings set policy_id = :successor, fingerprint = :fp, updated_at = now()
                         where id = :id
                        """, new MapSqlParameterSource().addValue("successor", successorPolicyId)
                        .addValue("fp", successorFingerprint).addValue("id", finding.findingId()));
            }
        }
    }

    public record MigrationPreview(UUID tenantId, int legacySelections, int selectionCopies, int retirements,
                                   int scopeCopies, int overrideCopies, int parameterManualReviews,
                                   int openFindingsToClose, int openFindingsReconciled,
                                   List<String> blockers, List<MigrationAction> actions) {}
    public record MigrationResult(UUID tenantId, int legacySelections, int selectionCopies, int retirements,
                                  int scopeCopies, int overrideCopies, int parameterManualReviews,
                                  int openFindingsToClose, int openFindingsReconciled, List<MigrationAction> actions) {}
    public record MigrationAction(String legacyDetectorId, String disposition, String closureReason, String sourceSelection,
                                  List<SelectionCopy> selectionCopies, ScopeCopy scopeCopy, List<OverrideCopy> overrideCopies,
                                  boolean manualConfigurationReview, int openFindingsToClose,
                                  boolean removeLegacyConfiguration, String reconcileToPolicyId, int openFindingsToReconcile) {
        static MigrationAction retire(LedgerEntry entry, String selection, int findings, boolean scope, int overrides, boolean parameters) {
            return new MigrationAction(entry.legacyDetectorId(), entry.disposition(), entry.closureReason(), selection, List.of(), null,
                    List.of(), false, findings, scope || overrides > 0 || parameters, null, 0);
        }
        static MigrationAction replace(LedgerEntry entry, String selection, List<SelectionCopy> copies, ScopeCopy scope,
                                       List<OverrideCopy> overrides, boolean manual, String reconcileToPolicyId, int findingsToReconcile) {
            return new MigrationAction(entry.legacyDetectorId(), entry.disposition(), entry.closureReason(), selection, List.copyOf(copies),
                    scope, overrides, manual, 0, !manual, reconcileToPolicyId, findingsToReconcile);
        }
    }
    public record SelectionCopy(String policyId, String selection) {}
    public record ScopeCopy(String policyId, Scope scope) {}
    public record OverrideCopy(String policyId, Override override) {}
    public record Scope(String mode, String conditionLogic, String conditionsJson) {}
    public record Override(UUID artifactId, String override, String reason) {}
    private record LedgerEntry(String legacyDetectorId, String disposition, List<String> successorPolicyIds, String closureReason) {}
    private record FindingSubject(UUID findingId, UUID subjectId) {}
}
