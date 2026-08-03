package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.domain.Tenant;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

/** Makes silent inventory and classification omissions explicit after each pipeline pass. */
@Service
public class AiGridReconciliationService {
    private final NamedParameterJdbcTemplate jdbc;
    private final AiGridCoverageService coverage;

    public AiGridReconciliationService(NamedParameterJdbcTemplate jdbc, AiGridCoverageService coverage) {
        this.jdbc = jdbc;
        this.coverage = coverage;
    }

    public void reconcile(Tenant tenant, UUID runId) {
        reconcile(tenant, runId, coverage.expectedCandidates(runId));
    }

    public void reconcile(Tenant tenant, UUID runId,
                          List<AiGridCoverageService.CoverageItem> candidates) {
        List<ArtifactState> artifacts = jdbc.query("""
                select distinct a.id,
                       exists (select 1 from ai_grid_artifact_classifications c
                                where c.artifact_id = a.id and c.state = 'CLASSIFIED') classified
                  from ai_security_artifacts a
                  join ai_grid_snapshot_manifests m on m.artifact_id = a.id and m.run_id = :runId
                """, Map.of("runId", runId), (rs, n) -> new ArtifactState(
                rs.getObject("id", UUID.class), rs.getBoolean("classified")));
        Map<UUID, Integer> expectedByArtifact = new HashMap<>();
        for (AiGridCoverageService.CoverageItem candidate : candidates) {
            expectedByArtifact.merge(candidate.artifactId(), 1, Integer::sum);
        }
        for (ArtifactState artifact : artifacts) {
            if (!artifact.classified()) {
                upsert(tenant, runId, artifact.id(), null, "UNKNOWN_TECHNOLOGY",
                        "Artifact technology could not be mapped to the governed registry",
                        "Add or correct the technology mapping and re-run classification");
            } else {
                resolve(tenant, artifact.id(), "UNKNOWN_TECHNOLOGY");
            }
            if (expectedByArtifact.getOrDefault(artifact.id(), 0) == 0) {
                upsert(tenant, runId, artifact.id(), null, "NO_POLICY_COVERAGE",
                        "No published policy is applicable to this artifact type and native technology",
                        "Review the family × control-dimension matrix and publish applicable policy coverage");
            } else {
                resolve(tenant, artifact.id(), "NO_POLICY_COVERAGE");
            }
            resolve(tenant, artifact.id(), "MISSING_ASSESSMENT");
        }
        for (AiGridCoverageService.CoverageItem candidate : candidates) {
            if (!candidate.assessmentPresent()) {
                upsert(tenant, runId, candidate.artifactId(), candidate.policyId(), "MISSING_ASSESSMENT",
                        "Published policy " + candidate.policyId() + " " + candidate.policyVersion()
                                + " has no assessment record for this artifact in the immutable run",
                        "Replay the run or investigate the assessment pipeline omission");
            }
        }
    }

    /** Reconciles tenant posture against the materialized union of all authoritative scope heads. */
    public void reconcileCurrent(Tenant tenant, UUID epochId, UUID triggerRunId) {
        jdbc.update("""
                update ai_grid_coverage_gaps set status = 'RESOLVED', resolved_at = now(), last_observed_at = now()
                 where coverage_epoch_id is not null and status = 'OPEN'
                """, Map.of());
        List<CurrentArtifact> artifacts = jdbc.query("""
                select a.artifact_id, a.technology_id, a.owner_name,
                       count(c.policy_id) candidate_count
                  from ai_grid_current_coverage_artifacts a
                  left join ai_grid_current_expected_candidates c
                    on c.epoch_id = a.epoch_id and c.artifact_id = a.artifact_id
                 where a.epoch_id = :epochId
                 group by a.artifact_id, a.technology_id, a.owner_name
                """, Map.of("epochId", epochId), (rs, n) -> new CurrentArtifact(
                rs.getObject("artifact_id", UUID.class), rs.getString("technology_id"),
                rs.getString("owner_name"), rs.getLong("candidate_count")));
        for (CurrentArtifact artifact : artifacts) {
            if ("UNCLASSIFIED".equals(artifact.technologyId())) {
                upsert(tenant, triggerRunId, epochId, artifact.id(), null, "UNKNOWN_TECHNOLOGY",
                        "Artifact technology could not be mapped to the governed registry",
                        "Add or correct the technology mapping and refresh coverage");
            }
            if (artifact.candidateCount() == 0) {
                upsert(tenant, triggerRunId, epochId, artifact.id(), null, "NO_POLICY_COVERAGE",
                        "No published policy is applicable to this artifact type and native technology",
                        "Review the family × control-dimension matrix and publish applicable policy coverage");
            }
            if ("UNOWNED".equals(artifact.ownerName())) {
                upsert(tenant, triggerRunId, epochId, artifact.id(), null, "UNRESOLVED_OWNER",
                        "No authoritative or candidate owner signal is available",
                        "Confirm an accountable owner or add an approved ownership mapping");
            }
        }
        for (AiGridCoverageService.CoverageItem candidate : coverage.currentCandidates()) {
            if (!candidate.assessmentPresent()) {
                upsert(tenant, triggerRunId, epochId, candidate.artifactId(), candidate.policyId(),
                        "MISSING_ASSESSMENT", "Published policy " + candidate.policyId() + " "
                                + candidate.policyVersion() + " has no assessment for its authoritative artifact snapshot",
                        "Replay the source run or investigate the assessment pipeline omission");
            } else if ("NO_DECISION".equals(candidate.decision()) || "ERROR".equals(candidate.decision())) {
                String state = currentGapState(candidate);
                upsert(tenant, triggerRunId, epochId, candidate.artifactId(), candidate.policyId(), state,
                        candidate.missingEvidenceJson(),
                        "Restore required permissions or evidence and reassess the authoritative scope");
            }
        }
    }

    private void upsert(Tenant tenant, UUID runId, UUID artifactId, String policyId,
                        String state, String reason, String action) {
        upsert(tenant, runId, null, artifactId, policyId, state, reason, action);
    }

    private void upsert(Tenant tenant, UUID runId, UUID epochId, UUID artifactId, String policyId,
                        String state, String reason, String action) {
        String fingerprint = sha256(tenant.getId() + "|" + artifactId + "|"
                + (policyId == null ? "-" : policyId) + "|" + state);
        jdbc.update("""
                insert into ai_grid_coverage_gaps (id, tenant_id, fingerprint, run_id, coverage_epoch_id,
                    artifact_id, policy_id, state, reason, required_action)
                values (:id, :tenantId, :fingerprint, :runId, :epochId, :artifactId, :policyId, :state, :reason, :action)
                on conflict (tenant_id, fingerprint) do update set run_id = excluded.run_id,
                    coverage_epoch_id = excluded.coverage_epoch_id, reason = excluded.reason,
                    required_action = excluded.required_action, status = 'OPEN',
                    last_observed_at = now(), resolved_at = null
                """, new MapSqlParameterSource().addValue("id", UUID.randomUUID()).addValue("tenantId", tenant.getId())
                .addValue("fingerprint", fingerprint).addValue("runId", runId).addValue("epochId", epochId)
                .addValue("artifactId", artifactId)
                .addValue("policyId", policyId).addValue("state", state).addValue("reason", reason)
                .addValue("action", action));
    }

    private String currentGapState(AiGridCoverageService.CoverageItem candidate) {
        if ("ERROR".equals(candidate.decision())) return "COLLECTION_ERROR";
        return switch (candidate.evidenceReadiness() == null ? "" : candidate.evidenceReadiness()) {
            case "INCOMPLETE_SCOPE" -> "INCOMPLETE_SCOPE";
            case "STALE" -> "STALE_EVIDENCE";
            case "UNSUPPORTED" -> "UNSUPPORTED";
            case "LOW_CONFIDENCE" -> "LOW_CONFIDENCE";
            default -> "MISSING_FACTS";
        };
    }

    private void resolve(Tenant tenant, UUID artifactId, String state) {
        jdbc.update("""
                update ai_grid_coverage_gaps set status = 'RESOLVED', resolved_at = now(), last_observed_at = now()
                 where tenant_id = :tenantId and artifact_id = :artifactId and state = :state and status = 'OPEN'
                """, Map.of("tenantId", tenant.getId(), "artifactId", artifactId, "state", state));
    }

    private String sha256(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (Exception e) { throw new IllegalStateException("Unable to fingerprint coverage gap", e); }
    }
    private record ArtifactState(UUID id, boolean classified) {}
    private record CurrentArtifact(UUID id, String technologyId, String ownerName, long candidateCount) {}
}
