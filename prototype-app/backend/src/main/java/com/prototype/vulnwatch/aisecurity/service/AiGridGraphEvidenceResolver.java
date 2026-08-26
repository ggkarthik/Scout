package com.prototype.vulnwatch.aisecurity.service;

import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * Single evidence boundary for graph-backed policy decisions. A direct posture policy gets one
 * fresh, run-bound hop; correlation engines may build their bounded paths from the same snapshots.
 */
@Service
public class AiGridGraphEvidenceResolver {
    public static final Duration DEFAULT_MAX_AGE = Duration.ofHours(24);
    private final NamedParameterJdbcTemplate jdbc;

    public AiGridGraphEvidenceResolver(NamedParameterJdbcTemplate jdbc) { this.jdbc = jdbc; }

    public DirectEvidence resolveDirect(UUID runId, UUID sourceArtifactId, List<String> requiredTypes,
                                        Instant asOf) {
        if (requiredTypes == null || requiredTypes.isEmpty()) return DirectEvidence.ready(List.of());
        List<Relationship> relationships = jdbc.query("""
                select r.id,r.source_artifact_id,r.target_artifact_id,r.relationship_type,r.observed_at,r.valid_until
                  from ai_grid_relationship_snapshots r
                 where r.run_id=:runId and r.source_artifact_id=:sourceId
                   and r.relationship_type in (:types) and r.observed_at<=:asOf
                   and (r.valid_until is null or r.valid_until>=:asOf)
                 order by r.relationship_type,r.observed_at desc,r.id desc
                """, new MapSqlParameterSource().addValue("runId", runId).addValue("sourceId", sourceArtifactId)
                .addValue("types", requiredTypes).addValue("asOf", Timestamp.from(asOf)), (rs, n) ->
                new Relationship(rs.getObject(1, UUID.class), rs.getObject(2, UUID.class), rs.getObject(3, UUID.class),
                        rs.getString(4), rs.getTimestamp(5).toInstant(),
                        rs.getTimestamp(6) == null ? null : rs.getTimestamp(6).toInstant()));
        return evaluate(requiredTypes, relationships, asOf, DEFAULT_MAX_AGE);
    }

    /** One immutable, run-bound relationship index shared by all direct posture evaluations. */
    public DirectIndex directIndexForRun(UUID runId, Instant asOf) {
        Map<UUID, List<Relationship>> bySource = new LinkedHashMap<>();
        jdbc.query("""
                select r.id,r.source_artifact_id,r.target_artifact_id,r.relationship_type,r.observed_at,r.valid_until
                  from ai_grid_relationship_snapshots r
                 where r.run_id=:runId and r.observed_at<=:asOf
                   and (r.valid_until is null or r.valid_until>=:asOf)
                 order by r.source_artifact_id,r.relationship_type,r.observed_at desc,r.id desc
                """, new MapSqlParameterSource().addValue("runId", runId).addValue("asOf", Timestamp.from(asOf)), rs -> {
            while (rs.next()) {
                Relationship relationship = new Relationship(rs.getObject(1, UUID.class), rs.getObject(2, UUID.class),
                        rs.getObject(3, UUID.class), rs.getString(4), rs.getTimestamp(5).toInstant(),
                        rs.getTimestamp(6) == null ? null : rs.getTimestamp(6).toInstant());
                bySource.computeIfAbsent(relationship.sourceArtifactId(), ignored -> new ArrayList<>()).add(relationship);
            }
            return null;
        });
        return new DirectIndex(bySource);
    }

    public DirectEvidence resolveDirect(DirectIndex index, UUID sourceArtifactId, List<String> requiredTypes,
                                        Instant asOf) {
        if (requiredTypes == null || requiredTypes.isEmpty()) return DirectEvidence.ready(List.of());
        List<Relationship> candidates = index.bySource().getOrDefault(sourceArtifactId, List.of()).stream()
                .filter(relationship -> requiredTypes.contains(relationship.type())).toList();
        return evaluate(requiredTypes, candidates, asOf, DEFAULT_MAX_AGE);
    }

    /** Immutable run graph used by bounded correlation traversal. */
    public List<GraphEdge> graphForRun(UUID runId, Instant asOf) {
        return jdbc.query("""
                select id,source_artifact_id,target_artifact_id,relationship_type,valid_from,valid_until
                  from ai_grid_relationship_snapshots where run_id=:runId
                   and valid_from<=:asOf and (valid_until is null or valid_until>=:asOf)
                 order by source_artifact_id,relationship_type,target_artifact_id
                """, new MapSqlParameterSource().addValue("runId", runId).addValue("asOf", Timestamp.from(asOf)),
                (rs, n) -> new GraphEdge(rs.getObject(1, UUID.class), rs.getObject(2, UUID.class),
                        rs.getObject(3, UUID.class), rs.getString(4), rs.getTimestamp(5).toInstant(),
                        rs.getTimestamp(6) == null ? null : rs.getTimestamp(6).toInstant()));
    }

    /** Latest-evidence profile for impact preview; it intentionally cannot claim an immutable run. */
    public DirectEvidence resolveLatest(UUID sourceArtifactId, List<String> requiredTypes, Instant asOf) {
        if (requiredTypes == null || requiredTypes.isEmpty()) return DirectEvidence.ready(List.of());
        List<Relationship> relationships = jdbc.query("""
                select distinct on (r.relationship_type,r.target_artifact_id)
                       r.id,r.source_artifact_id,r.target_artifact_id,r.relationship_type,r.observed_at,r.valid_until
                  from ai_grid_relationship_snapshots r
                 where r.source_artifact_id=:sourceId and r.relationship_type in (:types) and r.observed_at<=:asOf
                   and (r.valid_until is null or r.valid_until>=:asOf)
                 order by r.relationship_type,r.target_artifact_id,r.observed_at desc,r.id desc
                """, new MapSqlParameterSource().addValue("sourceId", sourceArtifactId).addValue("types", requiredTypes)
                .addValue("asOf", Timestamp.from(asOf)), (rs, n) -> new Relationship(rs.getObject(1, UUID.class),
                rs.getObject(2, UUID.class), rs.getObject(3, UUID.class), rs.getString(4), rs.getTimestamp(5).toInstant(),
                rs.getTimestamp(6) == null ? null : rs.getTimestamp(6).toInstant()));
        return evaluate(requiredTypes, relationships, asOf, DEFAULT_MAX_AGE);
    }

    static DirectEvidence evaluate(List<String> requiredTypes, List<Relationship> relationships,
                                   Instant asOf, Duration maxAge) {
        Map<String, Relationship> latest = new LinkedHashMap<>();
        for (Relationship relationship : relationships) latest.putIfAbsent(relationship.type(), relationship);
        List<String> absent = new ArrayList<>();
        List<String> stale = new ArrayList<>();
        for (String type : requiredTypes) {
            Relationship relationship = latest.get(type);
            if (relationship == null) absent.add(type);
            else if (relationship.observedAt().plus(maxAge).isBefore(asOf)) stale.add(type);
        }
        if (!stale.isEmpty()) return new DirectEvidence(Status.STALE, List.copyOf(latest.values()), List.copyOf(stale));
        if (!absent.isEmpty()) return new DirectEvidence(Status.ABSENT, List.copyOf(latest.values()), List.copyOf(absent));
        return DirectEvidence.ready(List.copyOf(latest.values()));
    }

    public enum Status { READY, ABSENT, STALE }
    public record Relationship(UUID id, UUID sourceArtifactId, UUID targetArtifactId, String type,
                               Instant observedAt, Instant validUntil) {}
    public record DirectIndex(Map<UUID, List<Relationship>> bySource) {
        public DirectIndex {
            Map<UUID, List<Relationship>> copy = new LinkedHashMap<>();
            bySource.forEach((source, relationships) -> copy.put(source, List.copyOf(relationships)));
            bySource = Map.copyOf(copy);
        }
    }
    public record GraphEdge(UUID id, UUID sourceArtifactId, UUID targetArtifactId, String type,
                            Instant validFrom, Instant validUntil) {}
    public record DirectEvidence(Status status, List<Relationship> relationships, List<String> issues) {
        static DirectEvidence ready(List<Relationship> relationships) {
            return new DirectEvidence(Status.READY, relationships, List.of());
        }
    }
}
