package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

/** Read-only, explainable prioritisation views over authoritative AI Grid evidence. */
@Service
public class AiExposureIntelligenceService {
    private final NamedParameterJdbcTemplate jdbc;
    private final TenantSchemaExecutionService tenantExecution;

    public AiExposureIntelligenceService(NamedParameterJdbcTemplate jdbc, TenantSchemaExecutionService tenantExecution) {
        this.jdbc = jdbc;
        this.tenantExecution = tenantExecution;
    }

    public Overview overview(Tenant tenant) {
        return tenantExecution.run(tenant, () -> {
            List<ExposurePriority> priorities = prioritiesInternal();
            long systems = count("select count(*) from ai_grid_systems where retired_at is null");
            long assets = count("select count(*) from ai_grid_current_coverage_artifacts");
            long incomplete = count("select count(*) from ai_security_snapshot_scopes where status in ('PARTIAL','FAILED')");
            long unsupported = count("select count(*) from ai_security_snapshot_scopes where status = 'UNSUPPORTED'");
            Instant authoritativeAt = jdbc.query("select materialized_at from ai_grid_current_coverage_state",
                    rs -> rs.next() && rs.getTimestamp(1) != null ? rs.getTimestamp(1).toInstant() : null);
            return new Overview(systems, assets, priorities.size(),
                    priorities.stream().filter(item -> isCriticalOrHigh(item.severity())).count(),
                    incomplete, unsupported, authoritativeAt, priorities.stream().limit(5).toList(),
                    recentActivityInternal().stream().limit(8).toList());
        });
    }

    public List<ExposurePriority> priorities(Tenant tenant) {
        return tenantExecution.run(tenant, this::prioritiesInternal);
    }

    public List<ActionQueueItem> actionQueue(Tenant tenant) {
        return tenantExecution.run(tenant, () -> {
            List<ActionQueueItem> items = new ArrayList<>();
            for (ExposurePriority exposure : prioritiesInternal()) {
                items.add(new ActionQueueItem(exposure.id(), "VALIDATED_EXPOSURE", exposure.title(), exposure.severity(),
                        exposure.priority(), exposure.owner(), exposure.provider(), exposure.accountId(),
                        exposure.breakpoint(), exposure.confidence(), exposure.lastObservedAt()));
            }
            items.addAll(jdbc.query("""
                    select f.id, f.title, coalesce(f.severity_override,
                           case when f.risk_score >= 9 then 'CRITICAL' when f.risk_score >= 7 then 'HIGH'
                                when f.risk_score >= 4 then 'MEDIUM' else 'LOW' end),
                           coalesce(a.owner_name, 'UNOWNED'), coalesce(a.provider, 'UNKNOWN'),
                           coalesce(a.account_id, 'UNKNOWN'), f.last_observed_at
                      from findings f
                      join finding_subjects fs on fs.finding_id = f.id and fs.subject_type = 'ARTIFACT'
                           and fs.subject_role = 'PRIMARY'
                      left join ai_security_artifacts a on a.id = fs.subject_id
                     where f.finding_kind = 'AI_POSTURE' and f.status = 'OPEN'
                    """, (rs, n) -> {
                String severity = rs.getString(3);
                return new ActionQueueItem(rs.getObject(1, UUID.class), "POLICY_FINDING", rs.getString(2), severity,
                        severityPriority(severity), rs.getString(4), rs.getString(5), rs.getString(6),
                        "Review the failed control and its evidence.", null, rs.getTimestamp(7).toInstant());
            }));
            return items.stream().sorted(Comparator.comparingInt(ActionQueueItem::priority).reversed()
                    .thenComparing(ActionQueueItem::lastObservedAt, Comparator.reverseOrder())).toList();
        });
    }

    public AssetPosture posture(Tenant tenant, UUID artifactId) {
        return tenantExecution.run(tenant, () -> {
            List<ControlPosture> controls = jdbc.query("""
                    select policy_id, selection, coalesce(evidence_readiness, 'UNKNOWN'),
                           coalesce(decision, 'NO_DECISION'), missing_evidence_json::text
                      from ai_grid_current_expected_candidates
                     where artifact_id = :artifactId
                     order by policy_id
                    """, Map.of("artifactId", artifactId), (rs, n) -> new ControlPosture(
                    rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4), rs.getString(5)));
            List<ExposurePriority> related = prioritiesInternal().stream()
                    .filter(item -> artifactId.equals(item.rootCauseArtifactId())).toList();
            return new AssetPosture(artifactId, controls, related);
        });
    }

    public List<ActivityItem> recentActivity(Tenant tenant) {
        return tenantExecution.run(tenant, this::recentActivityInternal);
    }

    private List<ExposurePriority> prioritiesInternal() {
        Instant now = Instant.now();
        return jdbc.query("""
                select p.id,p.title,p.severity,p.confidence,p.root_cause_artifact_id,p.breakpoint,p.last_observed_at,
                       coalesce(a.owner_name,'UNOWNED'),coalesce(a.provider,'UNKNOWN'),coalesce(a.account_id,'UNKNOWN'),
                       coalesce(a.business_criticality,''),coalesce(a.attributes_json::text,'{}')
                  from ai_grid_exposure_paths p
                  join ai_security_artifacts a on a.id=p.root_cause_artifact_id
                 where p.status='OPEN' and p.state='VALIDATED_EXPOSURE'
                """, (rs, n) -> priority(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3),
                rs.getDouble(4), rs.getObject(5, UUID.class), rs.getString(6), rs.getTimestamp(7).toInstant(),
                rs.getString(8), rs.getString(9), rs.getString(10), rs.getString(11), rs.getString(12), now))
                .stream().sorted(Comparator.comparingInt(ExposurePriority::priority).reversed()
                        .thenComparing(ExposurePriority::lastObservedAt, Comparator.reverseOrder())).toList();
    }

    private List<ActivityItem> recentActivityInternal() {
        List<ActivityItem> items = new ArrayList<>();
        items.addAll(jdbc.query("""
                select id,name,provider,account_id,first_observed_at from ai_security_artifacts
                 where first_observed_at >= now() - interval '14 days'
                 order by first_observed_at desc limit 20
                """, (rs, n) -> new ActivityItem("DISCOVERED", "ARTIFACT", rs.getObject(1, UUID.class),
                rs.getString(2), rs.getString(3), rs.getString(4), rs.getTimestamp(5).toInstant())));
        items.addAll(jdbc.query("""
                select p.id,p.title,coalesce(a.provider,'UNKNOWN'),coalesce(a.account_id,'UNKNOWN'),p.validated_at
                  from ai_grid_exposure_paths p join ai_security_artifacts a on a.id=p.root_cause_artifact_id
                 where p.state='VALIDATED_EXPOSURE' and p.validated_at >= now() - interval '14 days'
                 order by p.validated_at desc limit 20
                """, (rs, n) -> new ActivityItem("VALIDATED", "EXPOSURE", rs.getObject(1, UUID.class),
                rs.getString(2), rs.getString(3), rs.getString(4), rs.getTimestamp(5).toInstant())));
        return items.stream().sorted(Comparator.comparing(ActivityItem::observedAt).reversed()).toList();
    }

    private ExposurePriority priority(UUID id, String title, String severity, double confidence, UUID rootCauseArtifactId,
                                      String breakpoint, Instant lastObservedAt, String owner, String provider,
                                      String accountId, String criticality, String attributes, Instant now) {
        int severityPoints = switch (normalized(severity)) {
            case "CRITICAL" -> 35; case "HIGH" -> 27; case "MEDIUM" -> 16; default -> 8;
        };
        int confidencePoints = (int) Math.round(Math.max(0, Math.min(1, confidence)) * 25);
        int exposurePoints = isPublic(attributes) ? 20 : 0;
        int criticalityPoints = switch (normalized(criticality)) {
            case "CRITICAL" -> 10; case "HIGH" -> 7; case "MEDIUM" -> 4; default -> 0;
        };
        long ageDays = Math.max(0, Duration.between(lastObservedAt, now).toDays());
        int recencyPoints = ageDays <= 7 ? 10 : ageDays <= 30 ? 6 : 2;
        int total = severityPoints + confidencePoints + exposurePoints + criticalityPoints + recencyPoints;
        return new ExposurePriority(id, title, severity, Math.min(100, total), severityPoints, confidencePoints,
                exposurePoints, criticalityPoints, recencyPoints, confidence, rootCauseArtifactId, breakpoint,
                owner, provider, accountId, lastObservedAt);
    }

    private long count(String sql) { Long value = jdbc.queryForObject(sql, Map.of(), Long.class); return value == null ? 0 : value; }
    private static int severityPriority(String severity) { return switch (normalized(severity)) { case "CRITICAL" -> 95; case "HIGH" -> 80; case "MEDIUM" -> 55; default -> 30; }; }
    private static boolean isCriticalOrHigh(String severity) { return "CRITICAL".equals(normalized(severity)) || "HIGH".equals(normalized(severity)); }
    private static boolean isPublic(String attributes) { String value = normalized(attributes); return value.contains("\"publicnetworkaccess\":true") || value.contains("\"publicaccess\":true") || value.contains("\"publiclyaccessible\":true") || value.contains("\"publicendpoint\":true"); }
    private static String normalized(String value) { return value == null ? "" : value.trim().toUpperCase(Locale.ROOT); }

    public record Overview(long systemCount, long assetCount, long validatedExposureCount, long criticalHighExposureCount,
                           long incompleteScopeCount, long unsupportedScopeCount, Instant authoritativeAt,
                           List<ExposurePriority> topPriorities, List<ActivityItem> recentActivity) {}
    public record ExposurePriority(UUID id, String title, String severity, int priority, int severityPoints,
                                   int confidencePoints, int publicExposurePoints, int criticalityPoints,
                                   int recencyPoints, double confidence, UUID rootCauseArtifactId, String breakpoint,
                                   String owner, String provider, String accountId, Instant lastObservedAt) {}
    public record ActionQueueItem(UUID id, String kind, String title, String severity, int priority, String owner,
                                  String provider, String accountId, String remediation, Double confidence,
                                  Instant lastObservedAt) {}
    public record ControlPosture(String policyId, String selection, String evidenceReadiness, String decision,
                                 String missingEvidenceJson) {}
    public record AssetPosture(UUID artifactId, List<ControlPosture> controls, List<ExposurePriority> exposures) {}
    public record ActivityItem(String eventType, String subjectType, UUID subjectId, String name, String provider,
                               String accountId, Instant observedAt) {}
}
