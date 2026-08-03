package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AiGridRetentionService {
    private final NamedParameterJdbcTemplate jdbc;
    private final TenantSchemaExecutionService tenantExecution;
    private final TransactionTemplate transactions;

    public AiGridRetentionService(NamedParameterJdbcTemplate jdbc,
                                  TenantSchemaExecutionService tenantExecution,
                                  TransactionTemplate transactions) {
        this.jdbc = jdbc;
        this.tenantExecution = tenantExecution;
        this.transactions = transactions;
    }

    public RetentionStatus status(Tenant tenant) {
        return tenantExecution.run(tenant, () -> new RetentionStatus(policies(), counts(), activeHolds()));
    }

    public RetentionPolicy updatePolicy(Tenant tenant, PolicyCommand command, String actor) {
        if (!List.of("HOT", "ARCHIVE", "RESTRICTED_EVIDENCE").contains(command.retentionClass())) {
            throw badRequest("Invalid retention class");
        }
        if (command.retainDays() <= 0 || (command.archiveAfterDays() != null
                && (command.archiveAfterDays() < 0 || command.archiveAfterDays() >= command.retainDays()))) {
            throw badRequest("Invalid retention duration");
        }
        return tenantExecution.run(tenant, () -> transactions.execute(status -> {
            jdbc.update("""
                    update ai_grid_retention_policies set retain_days = :retainDays,
                        archive_after_days = :archiveDays, restricted = :restricted,
                        updated_by = :actor, reason = :reason, updated_at = now()
                     where retention_class = :class
                    """, new MapSqlParameterSource().addValue("retainDays", command.retainDays())
                    .addValue("archiveDays", command.archiveAfterDays()).addValue("restricted", command.restricted())
                    .addValue("actor", actor).addValue("reason", required(command.reason(), "reason"))
                    .addValue("class", command.retentionClass()));
            // Policy changes can extend existing commitments, but never shorten evidence retention automatically.
            jdbc.update("""
                    update ai_grid_snapshot_bodies
                       set retain_until = greatest(retain_until, created_at + (:days * interval '1 day'))
                     where retention_class = :class
                    """, Map.of("days", command.retainDays(), "class", command.retentionClass()));
            return policies().stream().filter(policy -> policy.retentionClass().equals(command.retentionClass()))
                    .findFirst().orElseThrow();
        }));
    }

    public EvidenceHold createHold(Tenant tenant, HoldCommand command, String actor) {
        if (!List.of("ACTIVE_FINDING", "EXCEPTION", "LEGAL_HOLD", "REPLAY_COMMITMENT")
                .contains(command.holdType())) throw badRequest("Invalid evidence hold type");
        return tenantExecution.run(tenant, () -> transactions.execute(status -> {
            UUID id = UUID.randomUUID();
            int inserted = jdbc.update("""
                    insert into ai_grid_evidence_holds
                        (id, tenant_id, snapshot_body_id, hold_type, reference_id, reason,
                         expires_at, created_by)
                    values (:id, :tenantId, :bodyId, :type, :referenceId, :reason, :expiresAt, :actor)
                    on conflict (tenant_id, snapshot_body_id, hold_type, reference_id) do nothing
                    """, new MapSqlParameterSource().addValue("id", id).addValue("tenantId", tenant.getId())
                    .addValue("bodyId", command.snapshotBodyId()).addValue("type", command.holdType())
                    .addValue("referenceId", required(command.referenceId(), "referenceId"))
                    .addValue("reason", required(command.reason(), "reason"))
                    .addValue("expiresAt", command.expiresAt() == null ? null : Timestamp.from(command.expiresAt()))
                    .addValue("actor", actor));
            if (inserted == 0) {
                id = jdbc.queryForObject("""
                        select id from ai_grid_evidence_holds where snapshot_body_id = :bodyId
                          and hold_type = :type and reference_id = :referenceId
                        """, Map.of("bodyId", command.snapshotBodyId(), "type", command.holdType(),
                        "referenceId", command.referenceId()), UUID.class);
            }
            if ("LEGAL_HOLD".equals(command.holdType())) {
                jdbc.update("update ai_grid_snapshot_bodies set legal_hold = true where id = :id",
                        Map.of("id", command.snapshotBodyId()));
            }
            if ("REPLAY_COMMITMENT".equals(command.holdType()) && command.expiresAt() != null) {
                jdbc.update("""
                        update ai_grid_snapshot_bodies set replay_commitment_until =
                            greatest(coalesce(replay_commitment_until, :expiresAt), :expiresAt)
                         where id = :id
                        """, Map.of("expiresAt", Timestamp.from(command.expiresAt()), "id", command.snapshotBodyId()));
            }
            return hold(id);
        }));
    }

    public EvidenceHold releaseHold(Tenant tenant, UUID holdId, String actor) {
        return tenantExecution.run(tenant, () -> transactions.execute(status -> {
            EvidenceHold existing = hold(holdId);
            jdbc.update("""
                    update ai_grid_evidence_holds set released_at = now(), released_by = :actor
                     where id = :id and released_at is null
                    """, Map.of("actor", actor, "id", holdId));
            if ("LEGAL_HOLD".equals(existing.holdType())) {
                jdbc.update("""
                        update ai_grid_snapshot_bodies set legal_hold = false where id = :bodyId
                          and not exists (select 1 from ai_grid_evidence_holds
                              where snapshot_body_id = :bodyId and hold_type = 'LEGAL_HOLD'
                                and released_at is null and (expires_at is null or expires_at > now()))
                        """, Map.of("bodyId", existing.snapshotBodyId()));
            }
            return hold(holdId);
        }));
    }

    public SweepResult sweep(Tenant tenant) {
        return tenantExecution.run(tenant, () -> transactions.execute(status -> {
            List<Body> bodies = jdbc.query("""
                    select id, retention_class, retention_state, created_at, retain_until,
                           legal_hold, replay_commitment_until
                      from ai_grid_snapshot_bodies order by created_at
                    """, (rs, n) -> new Body(rs.getObject("id", UUID.class), rs.getString("retention_class"),
                    rs.getString("retention_state"), rs.getTimestamp("created_at").toInstant(),
                    rs.getTimestamp("retain_until").toInstant(), rs.getBoolean("legal_hold"),
                    instant(rs, "replay_commitment_until")));
            Map<String, RetentionPolicy> policyByClass = new java.util.HashMap<>();
            policies().forEach(policy -> policyByClass.put(policy.retentionClass(), policy));
            int retained = 0, archived = 0, blocked = 0, eligible = 0;
            for (Body body : bodies) {
                String decision;
                String reason;
                if (body.retainUntil().isAfter(Instant.now())) {
                    RetentionPolicy policy = policyByClass.get(body.retentionClass());
                    boolean shouldArchive = "HOT".equals(body.retentionClass()) && policy != null
                            && policy.archiveAfterDays() != null
                            && body.createdAt().plusSeconds(policy.archiveAfterDays() * 86400L).isBefore(Instant.now());
                    if (shouldArchive) {
                        jdbc.update("""
                                update ai_grid_snapshot_bodies set retention_class = 'ARCHIVE',
                                    retention_state = 'ARCHIVED' where id = :id
                                """, Map.of("id", body.id()));
                        decision = "ARCHIVE"; reason = "ARCHIVE_AGE_REACHED"; archived++;
                    } else {
                        decision = "RETAIN"; reason = "RETENTION_WINDOW_ACTIVE"; retained++;
                    }
                } else {
                    String protection = protection(body);
                    if (protection == null) {
                        jdbc.update("update ai_grid_snapshot_bodies set retention_state = 'PURGE_ELIGIBLE' where id = :id",
                                Map.of("id", body.id()));
                        decision = "PURGE_ELIGIBLE"; reason = "RETENTION_EXPIRED_UNPROTECTED"; eligible++;
                    } else {
                        jdbc.update("update ai_grid_snapshot_bodies set retention_state = 'PURGE_BLOCKED' where id = :id",
                                Map.of("id", body.id()));
                        decision = "PURGE_BLOCKED"; reason = protection; blocked++;
                    }
                }
                jdbc.update("""
                        insert into ai_grid_retention_decisions
                            (id, tenant_id, snapshot_body_id, decision, reason_code)
                        values (:id, :tenantId, :bodyId, :decision, :reason)
                        """, new MapSqlParameterSource().addValue("id", UUID.randomUUID())
                        .addValue("tenantId", tenant.getId()).addValue("bodyId", body.id())
                        .addValue("decision", decision).addValue("reason", reason));
            }
            return new SweepResult(bodies.size(), retained, archived, blocked, eligible);
        }));
    }

    private String protection(Body body) {
        if (body.legalHold()) return "LEGAL_HOLD";
        if (body.replayCommitmentUntil() != null && body.replayCommitmentUntil().isAfter(Instant.now())) {
            return "REPLAY_COMMITMENT";
        }
        Integer explicit = jdbc.queryForObject("""
                select count(*) from ai_grid_evidence_holds where snapshot_body_id = :id
                  and released_at is null and (expires_at is null or expires_at > now())
                """, Map.of("id", body.id()), Integer.class);
        if (explicit != null && explicit > 0) return "ACTIVE_EVIDENCE_HOLD";
        Integer activeFinding = jdbc.queryForObject("""
                select count(*) from ai_grid_snapshot_manifests m
                  join ai_grid_assessments a on a.snapshot_manifest_id = m.id
                  join findings f on f.assessment_id = a.id
                 where m.body_id = :id and f.status = 'OPEN'
                """, Map.of("id", body.id()), Integer.class);
        return activeFinding != null && activeFinding > 0 ? "ACTIVE_FINDING" : null;
    }

    private List<RetentionPolicy> policies() {
        return jdbc.query("""
                select retention_class, retain_days, archive_after_days, restricted,
                       updated_by, reason, updated_at from ai_grid_retention_policies
                 order by retention_class
                """, (rs, n) -> new RetentionPolicy(rs.getString("retention_class"), rs.getInt("retain_days"),
                (Integer) rs.getObject("archive_after_days"), rs.getBoolean("restricted"),
                rs.getString("updated_by"), rs.getString("reason"), rs.getTimestamp("updated_at").toInstant()));
    }

    private RetentionCounts counts() {
        return jdbc.queryForObject("""
                select count(*) bodies, coalesce(sum(byte_size), 0) bytes,
                       count(*) filter (where retention_state = 'ARCHIVED') archived,
                       count(*) filter (where retention_state = 'PURGE_BLOCKED') blocked,
                       count(*) filter (where retention_state = 'PURGE_ELIGIBLE') eligible
                  from ai_grid_snapshot_bodies
                """, Map.of(), (rs, n) -> new RetentionCounts(rs.getLong("bodies"), rs.getLong("bytes"),
                rs.getLong("archived"), rs.getLong("blocked"), rs.getLong("eligible")));
    }

    private List<EvidenceHold> activeHolds() {
        return jdbc.query("""
                select * from ai_grid_evidence_holds where released_at is null
                  and (expires_at is null or expires_at > now()) order by created_at desc
                """, (rs, n) -> mapHold(rs));
    }

    private EvidenceHold hold(UUID id) {
        EvidenceHold value = jdbc.query("select * from ai_grid_evidence_holds where id = :id",
                Map.of("id", id), rs -> rs.next() ? mapHold(rs) : null);
        if (value == null) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Evidence hold not found");
        return value;
    }

    private EvidenceHold mapHold(java.sql.ResultSet rs) throws java.sql.SQLException {
        return new EvidenceHold(rs.getObject("id", UUID.class), rs.getObject("snapshot_body_id", UUID.class),
                rs.getString("hold_type"), rs.getString("reference_id"), rs.getString("reason"),
                instant(rs, "expires_at"), instant(rs, "released_at"), rs.getString("created_by"),
                rs.getTimestamp("created_at").toInstant());
    }

    private Instant instant(java.sql.ResultSet rs, String column) throws java.sql.SQLException {
        Timestamp value = rs.getTimestamp(column);
        return value == null ? null : value.toInstant();
    }
    private String required(String value, String field) {
        if (value == null || value.isBlank()) throw badRequest(field + " is required");
        return value;
    }
    private ResponseStatusException badRequest(String message) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }

    private record Body(UUID id, String retentionClass, String retentionState, Instant createdAt,
                        Instant retainUntil, boolean legalHold, Instant replayCommitmentUntil) {}
    public record RetentionPolicy(String retentionClass, int retainDays, Integer archiveAfterDays,
                                  boolean restricted, String updatedBy, String reason, Instant updatedAt) {}
    public record RetentionCounts(long bodies, long retainedBytes, long archived, long purgeBlocked,
                                  long purgeEligible) {}
    public record RetentionStatus(List<RetentionPolicy> policies, RetentionCounts counts,
                                  List<EvidenceHold> activeHolds) {}
    public record EvidenceHold(UUID id, UUID snapshotBodyId, String holdType, String referenceId,
                               String reason, Instant expiresAt, Instant releasedAt, String createdBy,
                               Instant createdAt) {}
    public record SweepResult(int evaluated, int retained, int archived, int purgeBlocked, int purgeEligible) {}
    public record PolicyCommand(String retentionClass, int retainDays, Integer archiveAfterDays,
                                boolean restricted, String reason) {}
    public record HoldCommand(UUID snapshotBodyId, String holdType, String referenceId, String reason,
                              Instant expiresAt) {}
}
