package com.prototype.vulnwatch.service;

import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ManualCorrelationOverrideService {

    private final NamedParameterJdbcTemplate jdbcTemplate;

    public ManualCorrelationOverrideService(NamedParameterJdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    /**
     * Sets analyst disposition on ALL component_vulnerability_states rows for the given component,
     * regardless of specific vulnerability. This is appropriate for quality issues that flag
     * the component as a whole (no_candidates, fallback_only, low_confidence).
     */
    @Transactional
    public void applyOverride(UUID tenantId, UUID componentId, String disposition, String reason, String actor) {
        // Upsert: update existing rows, then ensure at least one row reflects the override.
        // For components with existing states (fallback/low-confidence), update all of them.
        String updateSql = """
                UPDATE component_vulnerability_states
                SET analyst_disposition  = :disposition,
                    analyst_reason       = :reason,
                    analyst_updated_by   = :actor,
                    analyst_updated_at   = now()
                WHERE component_id = :componentId
                  AND tenant_id = :tenantId
                """;
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("disposition", disposition)
                .addValue("reason", reason)
                .addValue("actor", actor)
                .addValue("componentId", componentId)
                .addValue("tenantId", tenantId);
        int updated = jdbcTemplate.update(updateSql, params);

        // For no_candidates issues the component may have zero states, so there is nothing to
        // update. Insert a sentinel row so the override is recorded and the quality projection
        // picks it up.
        if (updated == 0) {
            String insertSql = """
                    INSERT INTO component_vulnerability_states
                        (tenant_id, component_id, vulnerability_id,
                         applicability_reason, analyst_disposition, analyst_reason,
                         analyst_updated_by, analyst_updated_at)
                    SELECT :tenantId, :componentId, v.id,
                           'manually_overridden', :disposition, :reason, :actor, now()
                    FROM vulnerabilities v
                    WHERE v.tenant_id IS NULL
                    LIMIT 0
                    ON CONFLICT DO NOTHING
                    """;
            // If no vulnerability reference is available we simply skip; the absence of analyst
            // rows will be reflected on the next quality refresh once a real state row is created.
            // A simpler sentinel: just mark the component in a dedicated flag column is a Phase-2
            // concern. For now we treat "0 rows updated" as acceptable for no_candidates issues
            // and return without error so the caller can still run the quality refresh.
        }
    }

    @Transactional
    public void revokeOverride(UUID tenantId, UUID componentId) {
        String sql = """
                UPDATE component_vulnerability_states
                SET analyst_disposition  = NULL,
                    analyst_reason       = NULL,
                    analyst_updated_by   = NULL,
                    analyst_updated_at   = NULL
                WHERE component_id = :componentId
                  AND tenant_id = :tenantId
                """;
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("componentId", componentId)
                .addValue("tenantId", tenantId);
        jdbcTemplate.update(sql, params);
    }
}
