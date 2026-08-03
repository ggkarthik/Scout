package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.service.TenantContext;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

/**
 * Computes the R1 release gate from platform-produced validation evidence and explicitly recorded
 * operational evidence. External evidence can satisfy only named operational gates; it cannot override
 * answer-key or policy-release governance.
 */
@Service
public class AiGridR1CertificationService {
    public static final String RELEASE_ID = "R1";
    private static final List<String> EXTERNAL_GATES = List.of(
            "DISCOVERY_RECALL",
            "FIRST_RUN_UTILITY",
            "DETERMINISM_AND_ISOLATION",
            "ECONOMICS_AND_BUDGETS",
            "AWS_DESIGN_PARTNER_SOAK",
            "AZURE_DESIGN_PARTNER_SOAK");

    private final NamedParameterJdbcTemplate jdbc;
    private final TransactionTemplate transactions;
    private final ObjectMapper objectMapper;
    private final AiGridValidationGovernanceService validation;

    public AiGridR1CertificationService(NamedParameterJdbcTemplate jdbc, TransactionTemplate transactions,
                                        ObjectMapper objectMapper,
                                        AiGridValidationGovernanceService validation) {
        this.jdbc = jdbc;
        this.transactions = transactions;
        this.objectMapper = objectMapper;
        this.validation = validation;
    }

    public ReleaseReadiness readiness() {
        return TenantContext.runAsPlatform(() -> {
            List<Gate> gates = new ArrayList<>();
            gates.add(answerKeyGate("AWS"));
            gates.add(answerKeyGate("AZURE"));
            gates.add(policyGovernanceGate());
            Map<String, GateEvidence> evidence = latestExternalEvidence();
            for (String code : EXTERNAL_GATES) {
                GateEvidence item = evidence.get(code);
                if (item == null) {
                    gates.add(new Gate(code, "BLOCKED", "External release evidence has not been recorded", null,
                            null, null));
                } else if (!item.validUntil().isAfter(Instant.now())) {
                    gates.add(new Gate(code, "EXPIRED", item.rationale(), item.evidenceReference(),
                            item.validUntil(), item.recordedAt()));
                } else {
                    gates.add(new Gate(code, item.status(), item.rationale(), item.evidenceReference(),
                            item.validUntil(), item.recordedAt()));
                }
            }
            LatestDecision latest = latestDecision();
            boolean ready = gates.stream().allMatch(gate -> "PASS".equals(gate.status()));
            return new ReleaseReadiness(RELEASE_ID, ready, List.copyOf(gates),
                    latest == null ? null : latest.decision(), latest == null ? null : latest.reason(),
                    latest == null ? null : latest.decidedAt());
        });
    }

    public GateEvidence recordEvidence(EvidenceCommand command, String actor) {
        String gateCode = required(command.gateCode(), "gateCode").toUpperCase();
        if (!EXTERNAL_GATES.contains(gateCode)) {
            throw badRequest("gateCode is not an externally attestable R1 gate");
        }
        String status = required(command.status(), "status").toUpperCase();
        if (!List.of("PASS", "FAIL").contains(status)) throw badRequest("status must be PASS or FAIL");
        String reference = required(command.evidenceReference(), "evidenceReference");
        String rationale = required(command.rationale(), "rationale");
        if (command.validUntil() == null || !command.validUntil().isAfter(Instant.now())) {
            throw badRequest("validUntil must be in the future");
        }
        return TenantContext.runAsPlatform(() -> transactions.execute(tx -> {
            UUID id = UUID.randomUUID();
            jdbc.update("""
                    insert into platform.ai_grid_release_gate_evidence
                        (id, release_id, gate_code, status, evidence_reference, rationale,
                         valid_until, recorded_by)
                    values (:id, :releaseId, :gateCode, :status, :reference, :rationale,
                            :validUntil, :actor)
                    """, new MapSqlParameterSource().addValue("id", id).addValue("releaseId", RELEASE_ID)
                    .addValue("gateCode", gateCode).addValue("status", status)
                    .addValue("reference", reference).addValue("rationale", rationale)
                    .addValue("validUntil", java.sql.Timestamp.from(command.validUntil()))
                    .addValue("actor", required(actor, "actor")));
            return evidence(id);
        }));
    }

    public ReleaseDecision decide(String actor) {
        return TenantContext.runAsPlatform(() -> transactions.execute(tx -> {
            ReleaseReadiness readiness = readiness();
            String decision = readiness.ready() ? "APPROVED" : "BLOCKED";
            String reason = readiness.ready()
                    ? "All R1 release gates passed"
                    : "Blocked by " + readiness.gates().stream()
                    .filter(gate -> !"PASS".equals(gate.status())).map(Gate::code).toList();
            UUID id = UUID.randomUUID();
            jdbc.update("""
                    insert into platform.ai_grid_release_decisions
                        (id, release_id, decision, gate_snapshot_json, reason, decided_by)
                    values (:id, :releaseId, :decision, cast(:snapshot as jsonb), :reason, :actor)
                    """, new MapSqlParameterSource().addValue("id", id).addValue("releaseId", RELEASE_ID)
                    .addValue("decision", decision).addValue("snapshot", json(readiness.gates()))
                    .addValue("reason", reason).addValue("actor", required(actor, "actor")));
            return new ReleaseDecision(id, RELEASE_ID, decision, reason, readiness.gates());
        }));
    }

    private Gate answerKeyGate(String provider) {
        Boolean passed = jdbc.queryForObject("""
                select exists (
                    select 1
                      from platform.ai_grid_answer_key_environments e
                      join platform.ai_grid_answer_key_runs r on r.environment_id = e.id
                     where upper(e.provider) = :provider and e.lifecycle = 'CERTIFIED'
                       and e.review_due_at > now() and r.status = 'PASS'
                       and r.provenance_state = 'PLATFORM_RUN_BOUND'
                       and r.total_cases = r.matched_cases)
                """, Map.of("provider", provider), Boolean.class);
        String code = provider + "_ANSWER_KEY";
        return Boolean.TRUE.equals(passed)
                ? new Gate(code, "PASS", "Fresh certified platform-bound answer-key run passed", null, null, null)
                : new Gate(code, "BLOCKED", "Fresh certified platform-bound answer-key run required", null,
                null, null);
    }

    private Gate policyGovernanceGate() {
        List<PolicyVersion> policies = jdbc.query("""
                select policy_id, version from platform.ai_grid_policy_versions
                 where lifecycle = 'PUBLISHED' order by policy_id
                """, (rs, row) -> new PolicyVersion(rs.getString("policy_id"), rs.getString("version")));
        List<String> blocked = policies.stream()
                .filter(policy -> !validation.releaseReadiness(policy.policyId(), policy.version()).ready())
                .map(policy -> policy.policyId() + "@" + policy.version()).toList();
        if (policies.isEmpty()) {
            return new Gate("POLICY_RELEASE_GOVERNANCE", "BLOCKED", "No published R1 policies exist", null,
                    null, null);
        }
        return blocked.isEmpty()
                ? new Gate("POLICY_RELEASE_GOVERNANCE", "PASS",
                "All published policy versions have current answer-key and precision evidence", null, null, null)
                : new Gate("POLICY_RELEASE_GOVERNANCE", "BLOCKED",
                "Policies missing current release evidence: " + blocked, null, null, null);
    }

    private Map<String, GateEvidence> latestExternalEvidence() {
        List<GateEvidence> values = jdbc.query("""
                select distinct on (gate_code) id, gate_code, status, evidence_reference, rationale,
                       valid_until, recorded_by, recorded_at
                  from platform.ai_grid_release_gate_evidence
                 where release_id = :releaseId
                 order by gate_code, recorded_at desc
                """, Map.of("releaseId", RELEASE_ID), (rs, row) -> mapEvidence(rs));
        Map<String, GateEvidence> byCode = new LinkedHashMap<>();
        values.forEach(value -> byCode.put(value.gateCode(), value));
        return byCode;
    }

    private GateEvidence evidence(UUID id) {
        GateEvidence value = jdbc.query("""
                select id, gate_code, status, evidence_reference, rationale,
                       valid_until, recorded_by, recorded_at
                  from platform.ai_grid_release_gate_evidence where id = :id
                """, Map.of("id", id), rs -> rs.next() ? mapEvidence(rs) : null);
        if (value == null) throw new IllegalStateException("Stored release evidence was not found");
        return value;
    }

    private GateEvidence mapEvidence(java.sql.ResultSet rs) throws java.sql.SQLException {
        return new GateEvidence(rs.getObject("id", UUID.class), rs.getString("gate_code"),
                rs.getString("status"), rs.getString("evidence_reference"), rs.getString("rationale"),
                rs.getTimestamp("valid_until").toInstant(), rs.getString("recorded_by"),
                rs.getTimestamp("recorded_at").toInstant());
    }

    private LatestDecision latestDecision() {
        return jdbc.query("""
                select decision, reason, decided_at from platform.ai_grid_release_decisions
                 where release_id = :releaseId order by decided_at desc limit 1
                """, Map.of("releaseId", RELEASE_ID), rs -> rs.next()
                ? new LatestDecision(rs.getString("decision"), rs.getString("reason"),
                rs.getTimestamp("decided_at").toInstant()) : null);
    }

    private String json(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException("Unable to serialize release gate snapshot", exception);
        }
    }

    private String required(String value, String field) {
        if (value == null || value.isBlank()) throw badRequest(field + " is required");
        return value.trim();
    }

    private ResponseStatusException badRequest(String message) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }

    private record PolicyVersion(String policyId, String version) {}
    private record LatestDecision(String decision, String reason, Instant decidedAt) {}

    public record EvidenceCommand(String gateCode, String status, String evidenceReference,
                                  String rationale, Instant validUntil) {}
    public record GateEvidence(UUID id, String gateCode, String status, String evidenceReference,
                               String rationale, Instant validUntil, String recordedBy, Instant recordedAt) {}
    public record Gate(String code, String status, String rationale, String evidenceReference,
                       Instant validUntil, Instant recordedAt) {}
    public record ReleaseReadiness(String releaseId, boolean ready, List<Gate> gates,
                                   String latestDecision, String latestDecisionReason,
                                   Instant latestDecisionAt) {}
    public record ReleaseDecision(UUID id, String releaseId, String decision, String reason,
                                  List<Gate> gates) {}
}
