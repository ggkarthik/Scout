package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class DashboardNoiseReductionProjectionService {

    private static final TypeReference<Map<String, Long>> CATEGORY_COUNTS_TYPE = new TypeReference<>() { };

    private final NamedParameterJdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final OperationalMetricsService operationalMetricsService;

    public DashboardNoiseReductionProjectionService(
            NamedParameterJdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper,
            OperationalMetricsService operationalMetricsService
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
        this.operationalMetricsService = operationalMetricsService;
    }

    @Transactional
    public int refreshTenant(UUID tenantId) {
        if (tenantId == null) {
            return 0;
        }

        long startedAtNs = System.nanoTime();
        int statusCode = 200;
        try {
            MapSqlParameterSource params = new MapSqlParameterSource().addValue("tenantId", tenantId);
            long neverOpenedNotApplicable = queryForLong("""
                    SELECT COUNT(*)
                    FROM component_vulnerability_states state
                    WHERE state.tenant_id = :tenantId
                      AND state.applicability_state = 'NOT_APPLICABLE'
                      AND state.impact_state = 'NOT_IMPACTED'
                      AND lower(coalesce(state.applicability_reason, '')) NOT IN ('component_not_observed', 'component_inactive')
                      AND NOT EXISTS (
                          SELECT 1
                          FROM findings finding
                          WHERE finding.tenant_id = state.tenant_id
                            AND finding.component_id = state.component_id
                            AND finding.vulnerability_id = state.vulnerability_id
                      )
                    """, params);

            long deferredUnderInvestigation = queryForLong("""
                    SELECT COUNT(*)
                    FROM component_vulnerability_states state
                    WHERE state.tenant_id = :tenantId
                      AND state.applicability_state = 'UNKNOWN'
                      AND lower(coalesce(state.applicability_reason, '')) LIKE '%under_investigation%'
                      AND lower(coalesce(state.applicability_reason, '')) NOT IN ('component_not_observed', 'component_inactive')
                      AND NOT EXISTS (
                          SELECT 1
                          FROM findings finding
                          WHERE finding.tenant_id = state.tenant_id
                            AND finding.component_id = state.component_id
                            AND finding.vulnerability_id = state.vulnerability_id
                      )
                    """, params);

            Map<String, Long> categoryCounts = loadCategoryCounts(params);
            Instant computedAt = Instant.now();
            String categoryCountsJson = toJson(categoryCounts);

            params.addValue("neverOpenedNotApplicable", neverOpenedNotApplicable)
                    .addValue("deferredUnderInvestigation", deferredUnderInvestigation)
                    .addValue("categoryCountsJson", categoryCountsJson)
                    .addValue("lastComputedAt", toSqlTimestamp(computedAt));

            jdbcTemplate.update("""
                    INSERT INTO dashboard_noise_reduction_projection (
                        tenant_id,
                        never_opened_not_applicable,
                        deferred_under_investigation,
                        category_counts_json,
                        last_computed_at
                    )
                    VALUES (
                        :tenantId,
                        :neverOpenedNotApplicable,
                        :deferredUnderInvestigation,
                        CAST(:categoryCountsJson AS jsonb),
                        :lastComputedAt
                    )
                    ON CONFLICT (tenant_id) DO UPDATE SET
                        never_opened_not_applicable = EXCLUDED.never_opened_not_applicable,
                        deferred_under_investigation = EXCLUDED.deferred_under_investigation,
                        category_counts_json = EXCLUDED.category_counts_json,
                        last_computed_at = EXCLUDED.last_computed_at
                    """, params);
            return 1;
        } catch (RuntimeException ex) {
            statusCode = 500;
            throw ex;
        } finally {
            long durationMs = (System.nanoTime() - startedAtNs) / 1_000_000L;
            operationalMetricsService.record(
                    OperationalMetricsService.KEY_NOISE_PROJECTION_REFRESH,
                    durationMs,
                    statusCode
            );
        }
    }

    public void ensureTenantProjection(Tenant tenant) {
        if (tenant == null || tenant.getId() == null) {
            return;
        }
        if (projectionExists(tenant.getId())) {
            return;
        }
        refreshTenant(tenant.getId());
    }

    public ProjectionSnapshot getTenantProjection(Tenant tenant) {
        if (tenant == null || tenant.getId() == null) {
            return ProjectionSnapshot.empty();
        }
        ensureTenantProjection(tenant);
        return loadProjection(tenant.getId());
    }

    @Transactional(readOnly = true)
    public ProjectionSnapshot getProjectionStatus(Tenant tenant) {
        if (tenant == null || tenant.getId() == null) {
            return ProjectionSnapshot.empty();
        }
        return loadProjection(tenant.getId());
    }

    private Map<String, Long> loadCategoryCounts(MapSqlParameterSource params) {
        Map<String, Long> counts = new LinkedHashMap<>();
        jdbcTemplate.queryForList("""
                SELECT categorized.category, COUNT(*) AS category_count
                FROM (
                    SELECT CASE
                        WHEN lower(coalesce(state.applicability_reason, '')) LIKE '%stale_or_untrusted%' THEN 'VEX Stale Or Untrusted'
                        WHEN lower(coalesce(state.applicability_reason, '')) LIKE '%vex_not_affected%' THEN 'VEX Not Affected'
                        WHEN lower(coalesce(state.applicability_reason, '')) LIKE '%vex_fixed%' THEN 'VEX Fixed'
                        WHEN lower(coalesce(state.applicability_reason, '')) LIKE '%nvd_config_override_not_affected%' THEN 'NVD Configuration Not Affected'
                        WHEN lower(coalesce(state.applicability_reason, '')) LIKE '%exact_version_mismatch%'
                          OR lower(coalesce(state.applicability_reason, '')) LIKE '%below_introduced%'
                          OR lower(coalesce(state.applicability_reason, '')) LIKE '%at_or_above_fixed%'
                          OR lower(coalesce(state.applicability_reason, '')) LIKE '%below_start%'
                          OR lower(coalesce(state.applicability_reason, '')) LIKE '%above_end%'
                          OR lower(coalesce(state.applicability_reason, '')) LIKE '%mismatch%'
                            THEN 'Version Outside Affected Range'
                        WHEN lower(coalesce(state.precedence_reason, '')) LIKE '%highest_precedence_not_affected%'
                          AND (
                              lower(coalesce(state.selected_target_source, '')) LIKE '%csaf%'
                              OR lower(coalesce(state.selected_target_source, '')) LIKE '%advisory%'
                              OR lower(coalesce(state.selected_target_source, '')) LIKE '%ghsa%'
                          ) THEN 'Vendor Advisory Not Affected'
                        ELSE 'Correlation Not Affected'
                    END AS category
                    FROM component_vulnerability_states state
                    WHERE state.tenant_id = :tenantId
                      AND state.applicability_state = 'NOT_APPLICABLE'
                      AND state.impact_state = 'NOT_IMPACTED'
                      AND lower(coalesce(state.applicability_reason, '')) NOT IN ('component_not_observed', 'component_inactive')
                      AND NOT EXISTS (
                          SELECT 1
                          FROM findings finding
                          WHERE finding.tenant_id = state.tenant_id
                            AND finding.component_id = state.component_id
                            AND finding.vulnerability_id = state.vulnerability_id
                      )
                ) categorized
                GROUP BY categorized.category
                ORDER BY COUNT(*) DESC, categorized.category ASC
                """,
                params)
                .forEach(row -> counts.put(
                        Objects.toString(row.get("category"), "Correlation Not Affected"),
                        ((Number) row.get("category_count")).longValue()
                ));
        return Map.copyOf(counts);
    }

    private ProjectionSnapshot loadProjection(UUID tenantId) {
        MapSqlParameterSource params = new MapSqlParameterSource().addValue("tenantId", tenantId);
        return jdbcTemplate.query("""
                        SELECT never_opened_not_applicable,
                               deferred_under_investigation,
                               category_counts_json::text AS category_counts_json,
                               last_computed_at
                        FROM dashboard_noise_reduction_projection
                        WHERE tenant_id = :tenantId
                        """,
                params,
                rs -> {
                    if (!rs.next()) {
                        return ProjectionSnapshot.empty();
                    }
                    Instant lastComputedAt = rs.getTimestamp("last_computed_at") == null
                            ? null
                            : rs.getTimestamp("last_computed_at").toInstant();
                    return new ProjectionSnapshot(
                            rs.getLong("never_opened_not_applicable"),
                            rs.getLong("deferred_under_investigation"),
                            parseCategoryCounts(rs.getString("category_counts_json")),
                            lastComputedAt
                    );
                });
    }

    private boolean projectionExists(UUID tenantId) {
        MapSqlParameterSource params = new MapSqlParameterSource().addValue("tenantId", tenantId);
        Long count = jdbcTemplate.queryForObject("""
                SELECT COUNT(*)
                FROM dashboard_noise_reduction_projection
                WHERE tenant_id = :tenantId
                """, params, Long.class);
        return count != null && count > 0L;
    }

    private long queryForLong(String sql, MapSqlParameterSource params) {
        Long value = jdbcTemplate.queryForObject(sql, params, Long.class);
        return value == null ? 0L : value;
    }

    private Map<String, Long> parseCategoryCounts(String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            Map<String, Long> parsed = objectMapper.readValue(json, CATEGORY_COUNTS_TYPE);
            return parsed == null ? Map.of() : Map.copyOf(parsed);
        } catch (Exception ignored) {
            return Map.of();
        }
    }

    private String toJson(Map<String, Long> value) {
        try {
            return objectMapper.writeValueAsString(value == null ? Map.of() : value);
        } catch (Exception ex) {
            return "{}";
        }
    }

    private Timestamp toSqlTimestamp(Instant value) {
        return value == null ? null : Timestamp.from(value);
    }

    public record ProjectionSnapshot(
            long neverOpenedNotApplicable,
            long deferredUnderInvestigation,
            Map<String, Long> categoryCounts,
            Instant lastComputedAt
    ) {
        public static ProjectionSnapshot empty() {
            return new ProjectionSnapshot(0L, 0L, Map.of(), null);
        }

        public boolean ready() {
            return lastComputedAt != null;
        }

        public Long ageSeconds() {
            if (lastComputedAt == null) {
                return null;
            }
            return Math.max(0L, Duration.between(lastComputedAt, Instant.now()).getSeconds());
        }
    }
}
